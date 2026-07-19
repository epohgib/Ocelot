# TODO: Apply respawn fix to `mysql::flush_*()` queue flushers

## Context

Commit `8b1c9bf` ("fix stuck token-expire queue when consumer thread dies")
fixed the same bug pattern in `src/site_comm.cpp` (the `site_comm::flush_tokens`
/ `do_flush_tokens` pair). The pattern recurs identically in all five
`mysql::flush_*()` functions in `src/db.cpp`. Apply the same fix to each when
the priority warrants the time.

## The bug pattern

Each of the 5 flushers has this shape:

```cpp
void mysql::flush_<X>() {
    // ... acquire buffer lock + queue lock ...
    if (readonly) { <X>_buffer = ""; return; }
    size_t qsize = <X>_queue.size();
    if (verbose_flush || qsize > 0) logger->info(...);
    if (<X>_buffer.empty()) {            // BUG: early return
        return;
    }
    <X>_buffer.pop_back();
    <X>_queue.push(fmt::format("INSERT ...", <X>_buffer));
    <X>_buffer = "";
    stats.<X>_queue_size = qsize + 1;
    if (!<x>_active) {                   // never reached when buffer is empty
        std::thread thread(&mysql::do_flush_<X>, this);
        thread.detach();
    }
}
```

If the consumer thread dies (e.g. on a transient MySQL failure, statement
timeout, or deadlock), `<x>_active` is reset to `false` by the catch block
in the corresponding `do_flush_<X>`. But because the buffer is empty (no new
events arrived), the next tick of `flush_<X>` exits at the early-return and
never reaches the respawn check. The pending queue entries are stranded
forever, and the in-memory queue grows on every subsequent batch of writes
that the dead consumer was meant to process.

## Functions to patch

| Flusher                | File:line (early-return) | Active flag | File:line (spawn) |
|------------------------|--------------------------|-------------|-------------------|
| `mysql::flush_users`   | `src/db.cpp:402`         | `u_active`  | `src/db.cpp:416`  |
| `mysql::flush_torrents`| `src/db.cpp:436`         | `t_active`  | `src/db.cpp:452`  |
| `mysql::flush_snatches`| `src/db.cpp:472`         | `s_active`  | `src/db.cpp:484`  |
| `mysql::flush_peers`   | `src/db.cpp:508`         | `p_active`  | `src/db.cpp:558`  |
| `mysql::flush_tokens`  | `src/db.cpp:578`         | `tok_active`| see below         |

`flush_peers` is slightly different: it has two buffers
(`light_peer_buffer` and `heavy_peer_buffer`) and the early return checks
both:

```cpp
if (light_peer_buffer.empty() && heavy_peer_buffer.empty()) {
    return;
}
```

The push logic inside the two `if (!…_buffer.empty())` blocks (with the
`qsize >= 3000` backpressure cap) is correct and should be left as-is.

`mysql::flush_tokens` (in `src/db.cpp`, around line 564 onwards) follows the
same template as the other three single-buffer flushers.

## The fix

For each of the 5 flushers, the change is mechanical:

1. Remove the early `return` when the buffer is empty.
2. Wrap the buffer-push logic in `if (!<X>_buffer.empty()) { ... }`
   (or, for `flush_peers`, leave the two existing inner `if` blocks intact
   and just remove the outer combined check).
3. Replace the spawn condition with `if (!<x>_active && !<X>_queue.empty())`.
4. Set `<x>_active = true;` under the queue lock, immediately before the
   `std::thread(...)` call.

### Worked example: `mysql::flush_users`

Before (`src/db.cpp:388-420`):

```cpp
void mysql::flush_users() {
    std::lock_guard<std::mutex> ub_lock(user_buffer_lock);
    if (readonly) {
        user_buffer = "";
        return;
    }
    std::lock_guard<std::mutex> uq_lock(user_queue_lock);
    size_t qsize = user_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info(
            "flush_users() chunks: {}, first chunk len: {}",
            qsize, user_queue.front().size()
        );
    }
    if (user_buffer.empty()) {       // <-- BUG
        return;
    }
    user_buffer.pop_back();
    user_queue.push(
        fmt::format(
            "INSERT INTO users_leech_stats (UserID,Uploaded,Downloaded)"
            "VALUES{}"
            "ON DUPLICATE KEY UPDATE Uploaded=Uploaded+VALUES(Uploaded),Downloaded=Downloaded+VALUES(Downloaded)",
            user_buffer
        )
    );
    user_buffer = "";
    stats.user_queue_size = qsize + 1;
    if (!u_active) {
        std::thread thread(&mysql::do_flush_users, this);
        thread.detach();
    }
}
```

After:

```cpp
void mysql::flush_users() {
    std::lock_guard<std::mutex> ub_lock(user_buffer_lock);
    if (readonly) {
        user_buffer = "";
        return;
    }
    std::lock_guard<std::mutex> uq_lock(user_queue_lock);
    size_t qsize = user_queue.size();
    if (verbose_flush || qsize > 0) {
        logger->info(
            "flush_users() chunks: {}, first chunk len: {}",
            qsize, user_queue.front().size()
        );
    }
    if (!user_buffer.empty()) {
        user_buffer.pop_back();
        user_queue.push(
            fmt::format(
                "INSERT INTO users_leech_stats (UserID,Uploaded,Downloaded)"
                "VALUES{}"
                "ON DUPLICATE KEY UPDATE Uploaded=Uploaded+VALUES(Uploaded),Downloaded=Downloaded+VALUES(Downloaded)",
                user_buffer
            )
        );
        user_buffer = "";
        stats.user_queue_size = qsize + 1;
    }
    if (!u_active && !user_queue.empty()) {
        u_active = true;
        std::thread thread(&mysql::do_flush_users, this);
        thread.detach();
    }
}
```

Apply the same shape to `flush_torrents`, `flush_snatches`, `flush_tokens`
(substituting the appropriate buffer / queue / active-flag / function names
per the table above).

### `flush_peers` specifically

The outer combined-empty check is removed; the two inner blocks are kept
verbatim. The spawn block at the bottom of the function changes from
`if (!p_active) { ... }` to `if (!p_active && !peer_queue.empty()) {
p_active = true; ... }`. The two `qsize >= 3000` backpressure checks inside
the inner blocks stay as they are.

## `do_flush_*` counterpart changes

Each of the 5 `do_flush_<X>` functions (in `src/db.cpp`, after the
corresponding `flush_<X>`) needs two changes to mirror the site_comm fix
in commit `8b1c9bf`:

1. Remove the `<x>_active = true;` line at the very top of the function
   (now set under lock by `flush_<X>`).
2. Add a `catch (...)` clause after the existing `catch (std::exception&)`
   to ensure `<x>_active` is always reset to `false` even on non-std
   exceptions.

Worked example for `do_flush_users`:

```cpp
void mysql::do_flush_users() {
    // remove: u_active = true;
    try {
        while (user_queue.size() > 0) {
            // ... existing body unchanged ...
        }
    } catch (std::exception &er) {
        logger->error("Exception: " + std::string(er.what()));
    } catch (...) {                                  // <-- new
        logger->error("Unknown exception in do_flush_users");
    }
    u_active = false;
}
```

Same shape for `do_flush_torrents`, `do_flush_snatches`, `do_flush_peers`,
`do_flush_tokens` (substitute the appropriate function and flag names).

## Estimated size

Approximately 10 functions touched, ~50 lines net diff, almost all
mechanical. Suitable for a single commit. A reasonable commit message
would mirror the wording of `8b1c9bf`:

```
fix stuck write-flush queues when consumer thread dies

Mirror the site_comm fix to all five mysql::flush_*() functions and their
do_flush_* counterparts. Without this, a transient MySQL failure leaves
the pending inserts stranded in memory forever.
```

## Verification

Post-deploy:

1. **Happy path unchanged.** Trigger normal write load (peer announces,
   snatches, etc.) and confirm the relevant queue size logs
   (`flush_users() chunks: N` etc.) oscillate between 0 and a small
   number, then return to 0.
2. **Respawn path.** Force a transient MySQL failure against the running
   instance (e.g. `FLUSH HOSTS;` to invalidate the connection pool, or
   briefly `systemctl stop mysql`), wait for a write to fail, then
   re-enable MySQL. Within one `schedule_interval`, the corresponding
   `flush_<X>()` log line should reappear (showing the queue draining)
   and the `<x>_active` flag should be reset. The DB tables should
   receive the missing writes.
3. **No double-processing.** Because the consumer is FIFO and pops the
   queue head only on a successful MySQL statement, a single batch is
   inserted exactly once. Spot-check with `SELECT COUNT(*)` before and
   after a controlled failure.

## Why this is lower priority than the site_comm fix

MySQL connection failures are rarer in steady-state operation than HTTP
connection failures to the upstream site (the site may be down for
deployments, restarts, or TLS issues; the local MySQL socket rarely
goes away). The site_comm path is also on the freeleech-token hot path,
where a stranded queue causes a user-visible bug (freeleech not
expired). The mysql paths feed statistics tables; a brief backlog is
typically recovered automatically once the connection comes back and
the next write event triggers a normal spawn.

## Out of scope for this TODO

- Convert `<x>_active` to `std::atomic<bool>` (codebase-wide refactor;
  affects `src/db.h`, `src/site_comm.h`, `src/worker.h`).
- Add exponential backoff in the `do_flush_*` retry loops (mirrors
  the existing `// TODO: add exponential backoff` on line 127 of
  `src/site_comm.cpp`).
- Restructure `do_flush_*` to acquire the queue lock around
  `size()` / `front()` reads (currently lock-free, safe under the
  single-consumer model but fragile if the consumer is ever
  parallelized).
- Add a graceful shutdown path that joins detached threads instead
  of relying on `exit(0)`.
