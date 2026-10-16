# Plan: IPv6 support in Ocelot and Gazelle

Status: ready for review
Owner: @bh

Two repositories, one coordinated change (branches `feature/ipv6`):

- **Tracker** — `git@github.com:PhoenixProj/Ocelot.git` (upstream),
  branch `feature/ipv6`.
- **Site** — `git@github.com:PhoenixProj/pp.git` (Gazelle/PHP), branch
  `feature/ipv6`; schema managed by Phinx in `db/migrations/`.

Origin of the feature: OPSnet/Ocelot issue #6, on the historical
upstream of PhoenixProj/Ocelot:
https://github.com/OPSnet/Ocelot/issues/6
Upstream PR: open on `PhoenixProj/Ocelot` only after both workstreams
are tested.

Empornium reference repositories (architecture source, never code to
copy — see §11):
- Radiance, tracker: https://github.com/Empornium/Radiance (v1.1.6,
  `bd1829d`) — Ocelot fork with a working IPv4+IPv6 implementation.
- Luminance, site: https://github.com/Empornium/Luminance (`23b568c1`,
  v0.6.0) — Gazelle fork, companion of Radiance.

All decisions D1–D20 are made in this document. N1–N4 follow Empornium:
binary/CIDR IP model, `user_seedbox` dropped, IPv6 anti-cheat
implemented, tracker and site changed together and staged (§5, §7, §10).

---

## 1. Context

Ocelot on `master` (3.1.0) parses the `X-Forwarded-For` header with
`inet_pton(AF_INET, ...)` (`worker.cpp:371-393`) and therefore only
accepts IPv4. Consequences:

- A client on an IPv6-only connection gets the error from commit
  `b9cbaf7`, `"Tracker could not parse your X-Forwarded-For address
  (IPv6 is not supported)"`, and cannot announce.
- The `peer` struct stores the address as `uint32_t` in
  `addr_port::addr` (`peer.h:11-19`), 4 bytes, insufficient for IPv6.
- The compact response only contains `peers` (BEP 03), not `peers6`
  (BEP 07).
- The listener is IPv4-only: `socket(AF_INET, ...)` (`events.cpp:74-75`),
  `getpeername` into a `sockaddr_in` (`events.cpp:203-206`), and the
  worker is called with a `uint32_t remote_addr`
  (`worker.h:77`, `events.h` `connection_middleman`). A client that
  connects directly over IPv6 cannot even reach the tracker.
- The DB stores addresses as text: `xbt_files_users.ip varchar(15)`,
  `xbt_snatched.IP varchar(15)` (`gazelle.sql:140-174`), written through
  the raw SQL expression `inet_ntoa(ntohl(ap.addr))`
  (`worker.cpp:659,679`). The target model is binary, like Empornium
  (§4.4).

> Note: `CHANGES` records 3.1.0 released 2026-04-13, but `CMakeLists.txt`
> still declares `VERSION 3.0.0` (stale). Bump it separately from this
> feature.

### Reference branches, and why neither is a base

- `upstream/ipv6` on the `upstream` remote (`PhoenixProj/Ocelot`,
  commit `4e7e250`, 2018, identical to wuubi's `ipv6` branch) is **not
  usable**. Verified against the branch source: it does
  not compile against the vendored spdlog 1.15 (removed `_st` sink API)
  and is autotools-based; it passes `ip` instead of `ip_tmp` to
  `getaddrinfo`, discarding the header value; `private_ipv6()` ends with
  `|| true`, so it clears **every** IPv6; it applies `hex_decode()` to
  the announce IPs; and `record_peer` still takes a raw SQL string.
- `wuubi/Ocelot` (`fac0fd1`) has working BEP 07 logic but is
  structurally older (no `xxhash`, no `fmt::format`, raw-string
  `record_peer`). Merging it would regress years of work.
- `Empornium/Radiance` is the same lineage as ours (fork of Ocelot) and
  has a complete, working IPv4+IPv6 implementation. Use it as the
  **architecture reference only**, never copy its code (it predates
  `xxhash`, `fmt::format` and the typed `record_peer`).

**Decision:** implement IPv6 on our codebase, using Radiance for
architecture and wuubi for the range checks, but writing all code
against the current fork's style.

---

## 2. Goals

The change spans two repositories (tracker and site); goals 1–7 are the
tracker's, goal 8 is the site's, and both are needed for goal 3 to hold
end to end.

1. Ocelot accepts and processes announces from IPv6-only clients.
2. The compact response includes `peers6` per BEP 07.
3. Addresses are persisted as binary (`xbt_files_users.ipv4`/`ipv6`,
   `xbt_snatched.ipv4`/`ipv6`, plus `port`) and are available to the site
   for connectability and anti-cheat exactly like IPv4.
4. IPv4 behavior unchanged (zero regressions) during stage 1.
5. Global feature flag `enable_ipv6 = false` by default, explicit opt-in.
6. A dual-stack client announcing the same `peer_id` over both families
   is **one** peer, never two (see §4.2, §9.4 rationale).
7. Per-user opt-in `track_ipv6`, default 0.
8. Gazelle moves to the binary/CIDR IP model, drops `user_seedbox` and
   implements IPv6 anti-cheat, as Empornium's Luminance did (§7).

## 3. Non-goals

- IPv6 multicast and anycast (defined in BEP 07, unused by BEP 03).
- Cloudflare/CDN logic.
- Changing the `peers` wire format: it stays 6 bytes/peer.
- `compact=0` support for IPv6 (modern clients use `compact=1`).
- A connectability UX other than the one §7 specifies: the `user_seedbox`
  removal itself is in scope, the replacement lives in the Gazelle
  repository.
- Trusting `track_ipv6` from the announce query string: it is set by the
  site (profile or moderator), never by the client (§4.5).

---

## 4. Architectural decisions

### 4.1 IP detection: `getaddrinfo` with `AF_UNSPEC` and `AI_NUMERICHOST`

Replaces `inet_pton(AF_INET, ...)` on `X-Forwarded-For`. `getaddrinfo`
with `AI_NUMERICHOST` parses both families, never does DNS, and is
strictly numeric, so `1.2.3.4 evil.com` cannot be injected.

```cpp
struct addrinfo hint{}, *res = nullptr;
hint.ai_family = AF_UNSPEC;
hint.ai_flags = AI_NUMERICHOST;
int err = getaddrinfo(ip.c_str(), nullptr, &hint, &res);
if (err == 0) {
    if (res->ai_family == AF_INET)       { /* IPv4 */ }
    else if (res->ai_family == AF_INET6) { /* IPv6 */ }
    freeaddrinfo(res);
}
```

**Decision:** success is `err == 0`. Do **not** copy Radiance's
`inet_pton(...) != -1` (`worker.cpp:669-705`): `inet_pton` returns
`1/0/-1`, so `!= -1` also accepts a syntactically invalid string and
then reads an uninitialised `sockaddr`.

Rules:

- XFF is truncated at the first comma before parsing (already on master).
- On parse failure: log a warning and keep the socket address. Never a
  fatal error.
- **Never** apply `hex_decode()` to an IP.
- The address string handed to the worker carries its family explicitly
  (§4.8), so `worker::work` does not have to guess.

### 4.2 Peer storage: both families on one peer

The current `addr_port { uint32_t addr; uint16_t port; }` is the BEP 03
wire format (6 bytes) and is not touched. IPv6 needs 16+2 = 18 bytes
(BEP 07), so:

```cpp
class peer {
  public:
    user_ptr user;
    addr_port ap;              // IPv4, 6 compact bytes (unchanged)
    bool has_ipv4 = false;     // `ap` is a raw union with no empty state
    std::string ipv6;          // 16 raw bytes of in6_addr, "" if absent
    std::string ipv6_port;     // 18 compact bytes (16 addr + 2 port)
    // ... rest unchanged
};
```

**Decision:** one peer entry holds **both** addresses. The DB row is
keyed by `(peer_id, fid, uid)` and the in-memory key is
`xxh64(peer_id ‖ userid)` (`worker.cpp:501-504`), i.e. family-independent
(`5385c05`). Adding a family discriminator to the key would reintroduce
the over-counting bug fixed by `5385c05` (two swarm entries, one DB
row). See §9.4.

Consequences to implement:

- `has_ipv4` gates every use of `ap`: it is false for a v6-only peer, so
  `ap` must never be read when false.
- Address-change detection must compare **both** families
  (`has_ipv4` + `ap` bytes, and `ipv6`), not just the 6-byte buffer.
- Compact output emits `ap.addr_port` only when `has_ipv4`, and
  `ipv6_port` when `ipv6` is non-empty (§4.7).

### 4.3 Public/private validation

**Decision:** put the two functions in `misc_functions` (not in the
worker as Radiance does), so they are unit-testable:

```cpp
bool ipv4_is_public(in_addr addr);   // 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, 127/8
bool ipv6_is_public(in6_addr addr);
```

IPv4 ranges (as Radiance, already correct):

| Range | Reason |
|---|---|
| `10.0.0.0/8` | private |
| `172.16.0.0/12` | private |
| `192.168.0.0/16` | private |
| `169.254.0.0/16` | link-local |
| `100.64.0.0/10` | CGNAT |
| `127.0.0.0/8` | loopback |

IPv6 ranges, matched on the leading bytes of `s6_addr` (portable; do
**not** use `s6_addr32`/`s6_addr16`, which are glibc extensions):

| Prefix | Reason | Mask |
|---|---|---|
| `::/128` | unspecified | 16 bytes |
| `::1/128` | loopback | 16 bytes |
| `::ffff:0:0/96` | IPv4-mapped (normally already demoted, §4.8) | 12 bytes |
| `100::/64` | discard-only | 8 bytes |
| `2001:db8::/32` | documentation | 4 bytes |
| `2001::/32` | Teredo | 4 bytes |
| `2002::/16` | 6to4 | 2 bytes |
| `3ffe::/16` | 6bone, deprecated | 2 bytes |
| `fc00::/7` | unique local (ULA) | **1 byte masked `0xfe == 0xfc`** |
| `fe80::/10` | link-local | 2 bytes masked `0xffc0 == 0xfe80` |
| `fec0::/10` | site-local, deprecated | 2 bytes masked `0xffc0 == 0xfec0` |

> The ULA check must be `/7`, not `/16`. Radiance uses
> `ntohs(s6_addr16[0]) == 0xfc00`, which only covers `fc00::/16` and lets
> the commonly used `fd00::/8` through as public. Do not copy it.

No `is_development()` shortcut exists on master (no `__DEBUG_BUILD__`
define), so **tests must use publicly routable addresses** (e.g.
`2606:4700:4700::1111`), not `2001:db8::*`, which is rejected by design.

### 4.4 DB schema: binary addresses, like Empornium

**Decision (N1 = option A, D16):** adopt Empornium's binary model. The
site moves with it, so the migration is staged (§6.3) and the legacy
textual `ip` column is kept during the transition.

`xbt_files_users`:

```sql
`ipv4` varbinary(4)  DEFAULT NULL,   -- 4 bytes of in_addr,   network order
`ipv6` varbinary(16) DEFAULT NULL,   -- 16 bytes of in6_addr, network order
`port` int(6) NOT NULL DEFAULT 0,    -- the site connectability checker needs it
```

`xbt_snatched`, which also becomes **unique per `(uid, fid)`** (D20):

```sql
`ipv4` varbinary(4)  DEFAULT NULL,
`ipv6` varbinary(16) DEFAULT NULL,
PRIMARY KEY (`uid`, `fid`),
```

Today the table has no unique key and the flush uses `INSERT IGNORE`, so
re-snatches accumulate duplicate rows. Empornium fixed this with the same
primary key; we align (§6.2 deduplicates first).

`users_main`:

```sql
`track_ipv6` tinyint(1) NOT NULL DEFAULT 0,
```

The legacy textual `ip` / `IP` columns are kept and still written during
stage 1 (§6.3), so today's site keeps working unchanged. Empornium also
carries `ctime` on `xbt_files_users`; it is not needed by the §7 contract
and is deliberately not added.

**Decision: no index on `ipv4`/`ipv6`.** The tracker only writes these
columns and never queries them; the site's lookups go through its own
`ips`/CIDR table (§7.2), not through this table.

**Decision: fix the heavy `ON DUPLICATE KEY UPDATE`.** The current clause
(`db.cpp:527-531`) updates `active, uploaded, downloaded, upspeed,
downspeed, remaining, corrupt, timespent, announced, mtime` but **not**
`ip`. A peer re-announcing from a new address therefore never has its
stored address updated, which contradicts the intent of `5385c05`. The
clause gains `ip=VALUES(ip),ipv4=VALUES(ipv4),ipv6=VALUES(ipv6),
port=VALUES(port)`. This slightly changes IPv4 semantics (the column now
tracks the latest address instead of the first-seen one); it is the
behaviour `5385c05` intended and is recorded as D6.

`record_peer` and `record_snatch` take the binary addresses (`port` too
for peers) and format each as a `X'<hex>'` SQL literal, or `''` when
absent (`u->is_protected()` → both empty). Same injection-safety model
as today's `inet_ntoa(...)` expression: only validated bytes are
formatted, never user text.

### 4.5 Per-user opt-in: `track_ipv6`

`users_main.track_ipv6 TINYINT(1) NOT NULL DEFAULT 0`. Default 0:
existing users are not tracked on IPv6 until they opt in.

- `load_users` (`db.cpp:171-173`) selects the new column and stores it on
  the `user` object; `user` gains a `track_ipv6` field with
  getter/setter (`user.h`).
- The site pushes changes without a reload through the existing
  `update_user` API action (`worker.cpp:1062-1098`), extended with a
  `track_ipv6` parameter; `add_user` (`worker.cpp:1017-1030`) defaults it
  to false.
- Worker: after validation, `if (!u->track_ipv6()) ipv6.clear();`. A peer
  whose owner has not opted in is never recorded on IPv6, and its IPv6 is
  never offered to others (§4.7).

**Decision (default timing):** explicit opt-in for **both** existing and
new users (site default 0). Conservative and GDPR-friendly; flipping the
site default later is a one-line change with no tracker impact.

This matches Luminance exactly: a profile checkbox ("Allow the tracker
to broadcast your IPv6 address to the swarm") writes
`users_main.track_ipv6` and pushes it with
`update_user&passkey=...&track_ipv6=0|1`; moderators can set it too
(`takeedit.php`, `takemoderate.php`).

### 4.6 Global feature flag: `enable_ipv6 = false`

**Decision:** add the key to `config.cpp` (`add("enable_ipv6", false);`)
and to `ocelot.conf.dist`. Without the `add()` the key would resolve to
`dummy_setting` (`config.cpp:106-117`), i.e. always `false` plus a
`WARNING: Unrecognized setting` line on every read — the flag would be
inert and un-configurable.

Semantics, checked at the top of `worker::work`:

- `false` (default): the worker behaves as today for IPv4. An IPv6
  announce (socket address or XFF) is rejected with a clear client
  error, `"IPv6 tracking is disabled"`, in the same style as `b9cbaf7`,
  never a fatal error.
- `true`: detection, validation, storage, stats and BEP 07 are active.

Flipping it requires a config reload; the worker reads it in
`load_config`.

**Decision:** the flag does **not** gate the listener. Commit 7 opens the
IPv6 socket unconditionally; with the flag off, v6 clients connect and
are then rejected at the worker. This keeps a single kill switch for
behaviour while leaving socket management independent.

### 4.7 Wire format: additive `peers6`, and `external ip`

Include `peers6` only when **both** hold: the announcer used IPv6
(`p->ipv6` not empty) and the owner of the candidate peer being returned
has opted in (`candidate.user->track_ipv6()`). This mirrors Radiance
(`worker.cpp:879-882`), where the condition is on the peer being
returned, not on the requester.

```
d...5:peers<6*N bytes>6:peers6<18*M bytes>e
```

Each key is a bencode byte string (prefixed by its own byte length).
`peers` stays 6 bytes/peer (BEP 03); `peers6` is 18 bytes/peer
(16 bytes `in6_addr` + 2 bytes `port`, both network order). The two are
capped together by one `found_peers` counter, so the total never exceeds
`numwant`. Clients without BEP 07 ignore the key.

**Decision:** also emit `external ip` (BEP 24) with the announcer's own
address, IPv6 preferred:

```cpp
if (!p->ipv6.empty()) output += bencode_str("external ip") + bencode_str(inet6_text(p->ipv6));
else                  output += bencode_str("external ip") + bencode_str(inet_text(p->ap));
```

On master the recorded address already is the public one (XFF replaces
`remote_addr`, `worker.cpp:373-393`), so a single address is enough. This
differs from Radiance, which keeps a separate `public_ip` from
`real_ip_header`; porting that separation is out of scope.

### 4.8 Listener: dual-stack TCP, configurable bind, unix socket

**Decision (N5):** adopt Radiance's listener model, verified in commit
`7eef3e6` ("Full support for IPv6 interface and Unix sockets",
2019-10-21), which is also the commit that introduced the address
handling below.

New config key `listen_host`, default `*`:

- `*` or empty → bind all interfaces on both families;
  `getaddrinfo(NULL, listen_port, AI_PASSIVE, AF_UNSPEC)` yields
  `0.0.0.0` and `::`, matching today's `INADDR_ANY`;
- a space-separated list, e.g. `listen_host = 0.0.0.0 ::`;
- `unix:/path/to.sock` → a unix-domain listener.

Parse the value with a small `split()` helper (Radiance added one to
`misc_functions`; our fork has only a private `config::trim`, and
`config::load` preserves spaces inside values).

Per address: `getaddrinfo(AI_PASSIVE, PF_UNSPEC)` and **one socket per
result**, with `IPV6_V6ONLY=1` on the `AF_INET6` socket so the v4 and v6
listeners do not overlap, plus `SO_REUSEADDR`, `O_NONBLOCK`, `bind`,
`listen`. For unix sockets, `unlink` the path first and `chmod` it after
the bind.

State changes from a single socket to collections (`events.h`):
`std::vector<std::string> listen_hosts`, `std::vector<int>
listen_sockets`, `std::map<int, ev::io*> listen_events` (exactly
Radiance's types). `reload_config` must tear down and rebuild all of
them when **either** the port or the host list changes, and re-`listen()`
with the new backlog when only `max_connections` changes.
`handle_connect` must construct the middleman with `watcher.fd`,
**not** the old member `listen_socket`: with more than one listening fd
the member points at the wrong socket. This is the one detail of
`7eef3e6` that earlier drafts missed.

Address plumbing: `worker::work`/`worker::announce` take

```cpp
struct client_addr_t { std::string ip; uint16_t family; };  // AF_INET / AF_INET6 / AF_UNIX
```

Commit 2 introduces the struct (`events.cpp` fills it from the IPv4
`getpeername`); Commit 7 fills it from the v6 and unix paths. Read the
peer with `sockaddr_storage` + `inet_ntop`:

- `AF_INET` → `family = AF_INET`, ip from `sin_addr`;
- `AF_INET6` → `family = AF_INET6`, ip from `sin6_addr`; **demote
  `::ffff:a.b.c.d` to IPv4 first**, otherwise `ipv6_is_public` rejects it
  as IPv4-mapped;
- `AF_UNIX` → `ip` empty, the address must come from
  `X-Forwarded-For`. If the header is absent or `ignore_xff` is set,
  reject with a clear error: no socket address exists.

The listener always accepts IPv6, independently of `enable_ipv6` (D7).

### 4.9 Statistics

Add two atomics to `stats_t` (`ocelot.h:83-115`): `ipv4_peers`,
`ipv6_peers`. They are independent of `leechers`/`seeders` (a peer can be
both a seeder and IPv6).

Accounting must match the peer lifecycle:

- `add_leecher` / `add_seeder` increment the counter of the family (or
  families) actually set on the peer.
- Removal on `event=stopped` (`worker.cpp:781-790`) decrements the same.
- `reap_peers` recomputes `stats.leechers`/`seeders` from scratch at the
  end of the scan; it must recompute `ipv4_peers`/`ipv6_peers` the same
  way in the same pass, then assign. Increment-only accounting drifts
  after a reap.
- `report.cpp` (`stats` action, around lines 102-104) gains
  `ipv4 peers` / `ipv6 peers` items so Gazelle and the Grafana dashboard
  can show them.

---

## 5. Roadmap

Two workstreams, one per repository, sequenced in "Sequencing across the
two repositories" at the end of this section:

- **Part A — tracker (Ocelot):** commits 1–7 below.
- **Part B — site (Gazelle):** commits S1–S6, detailed in §7.

Each commit is compilable and testable on its own. §10 refers to the
tracker commits as "Commit N".

**Part A — tracker (Ocelot, this repository):**

### Commit 1: foundations — config flag and validation helpers

**Files touched:** `src/config.cpp`, `ocelot.conf.dist`,
`src/misc_functions.h`, `src/misc_functions.cpp`

**What:** `add("enable_ipv6", false);` plus the `.dist` entry; add
`ipv4_is_public` and `ipv6_is_public` with the ranges of §4.3
(includes `<arpa/inet.h>` / `<netdb.h>` where needed). No behaviour
change yet: nothing reads either.

**Test:** a small unit test (or `assert`s in a test main) covering every
rejected range, especially `fd00::1` (must be private — the Radiance
bug), `fe80::1`, `::1`, `2001:db8::1`, and accepted samples
`2606:4700:4700::1111`, `8.8.8.8`.

**Estimate:** 1 hour, ~60 lines.

### Commit 2: parse socket and X-Forwarded-For addresses as v4/v6

**Files touched:** `src/worker.h`, `src/worker.cpp`, `src/events.cpp`

**What:** introduce `client_addr_t` (§4.8) and thread it through
`worker::work`/`worker::announce` in place of `uint32_t remote_addr` /
`addr_port`. Parse XFF with `getaddrinfo(AF_UNSPEC, AI_NUMERICHOST)` and
`err == 0` (§4.1); build the `addr_port` from the parsed `in_addr` when
the family is IPv4. An IPv6 XFF is parsed and carried in the struct but
no IPv6 logic consumes it yet: it is logged and the socket IPv4 address
is used. `events.cpp` fills `{ ip, AF_INET }` from the existing IPv4
`getpeername`. `enable_ipv6` is not consulted yet.

**Test:** tcpdump on port 31000, verify IPv4 XFF works as before; IPv6
XFF logs a warning but is not a fatal error; garbage XFF is discarded.

**Estimate:** 1.5 hours, ~45 lines changed.

### Commit 3: accept `ipv6=` / `ipv4=` / `ip=` as a secondary address

**Files touched:** `src/worker.cpp`

**What:** read the BEP 03/07 announce parameters with the same
`getaddrinfo` logic and **merge** them with the connection address
instead of replacing it:

- the address of the connection (socket, or XFF when trusted) stays
  authoritative for its own family;
- `ipv6=` / `ipv4=` / `ip=` may fill the **other** family slot only.

This is what lets a dual-stack client connected over IPv4 advertise its
IPv6 address (and vice versa) so mixed swarms work, while a spoofed
parameter can never overwrite the address the tracker actually observed.
Private/unroutable values are dropped by `*_is_public`.

**Test:** announce over IPv4 with `&ipv6=2606:4700:4700::1111` and verify
both families end up on the peer; announce `&ipv6=fd00::1` and verify it
is dropped.

**Estimate:** 1 hour, ~25 lines.

### Commit 4: `peer` stores both address families

**Files touched:** `src/peer.h`, `src/worker.h`, `src/worker.cpp`

**What:** add `has_ipv4`, `ipv6`, `ipv6_port` to `peer` (§4.2); update
`add_leecher`/`add_seeder`/`move_*`/`insert_seeder` signatures to carry
the new fields; rework the address-change check (`worker.cpp:645-648`)
to compare both families and set `peer_changed`. No IPv6 validation or
recording yet.

**Test:** compile; IPv4 behaviour identically unchanged; a v6-only peer
is constructed with `has_ipv4 == false`.

**Estimate:** 1 hour, ~40 lines.

### Commit 5: dual-stack validation, recording and statistics

**Files touched:** `src/worker.cpp`, `src/db.h`, `src/db.cpp`,
`src/ocelot.h`, `src/user.h`, `src/report.cpp`

**What:**

- validate both families with `ipv4_is_public` / `ipv6_is_public`; drop
  invalid values individually;
- if both are empty after validation, return `error("Invalid IP
  detected")`;
- apply `if (!u->track_ipv6()) ipv6.clear();` to the in-memory peer and
  to what is recorded;
- `enable_ipv6` gate at the top of `worker::work` (§4.6);
- add `track_ipv6` to `user` (getter/setter/ctor); select it in
  `load_users`; accept it in the `update_user` action (and default it in
  `add_user`);
- `record_peer` takes the two binary addresses plus `port`, and
  `record_snatch` the two addresses; the worker formats each as a
  `X'<hex>'` literal or `''` (`u->is_protected()` → empty) from
  validated bytes only — same injection-safety model as today's
  `inet_ntoa(...)` expression;
- flush SQL: write `ipv4`, `ipv6`, `port` in the heavy `xbt_files_users`
  insert and add
  `ip=VALUES(ip),ipv4=VALUES(ipv4),ipv6=VALUES(ipv6),port=VALUES(port)`
  to its `ON DUPLICATE KEY UPDATE`, still writing the legacy `ip` during
  stage 1 (§6.3); `xbt_snatched` moves from `INSERT IGNORE` to
  `INSERT ... ON DUPLICATE KEY UPDATE tstamp=VALUES(tstamp),
  ipv4=VALUES(ipv4),ipv6=VALUES(ipv6)`, backed by the new primary key
  (D20);
- `stats.ipv4_peers` / `stats.ipv6_peers` (§4.9), including the
  `reap_peers` recompute.

**Test:**

- IPv4-only announce: no regression, `ipv6_peers == 0`, `ipv4` set
  (binary) and `ipv6` NULL.
- IPv6 announce, `track_ipv6=1`, `enable_ipv6=true`: peer counted,
  `xbt_files_users.ipv6` set, `ipv4` NULL.
- same with `track_ipv6=0`: not recorded on IPv6.
- same with `enable_ipv6=false`: clear client error.
- address change is persisted (`ipv4`/`ipv6`/`port` updated on
  duplicate).
- `port` matches the announced port (used by the site checker).
- `reap_peers`: after a reap the two family counters match the swarms.

**Estimate:** 4-5 hours, ~130 lines.

### Commit 6: emit BEP 07 `peers6` and BEP 24 `external ip`

**Files touched:** `src/worker.cpp`

**What:** generate `peers6` (18 bytes/peer) under the conditions of
§4.7, sharing the `found_peers`/`numwant` budget with `peers`, and add
the `external ip` key.

**Test:** qBittorrent or Deluge (BEP 07) over IPv6 sees IPv6 peers and
downloads from them; rtorrent 0.9.8 (no BEP 07) keeps working; a v6
announcer does not receive v4 peers without IPv6.

**Estimate:** 2 hours, ~50 lines.

### Commit 7: listener — dual-stack, configurable bind, unix socket

**Files touched:** `src/config.cpp`, `ocelot.conf.dist`,
`src/misc_functions.h`, `src/misc_functions.cpp`, `src/events.h`,
`src/events.cpp`

**What:** adopt Radiance `7eef3e6` (§4.8):

- add `add("listen_host", "*")` and the `.dist` entry documenting the
  `*` / `0.0.0.0 ::` / `unix:/path` syntax;
- add a `split()` helper to `misc_functions`;
- replace the single `socket(AF_INET, ...)` / `bind` in
  `create_listen_socket` with `create_tcp_server` (loop over
  `getaddrinfo(AI_PASSIVE, PF_UNSPEC)`, `IPV6_V6ONLY=1`, `SO_REUSEADDR`,
  non-blocking, bind/listen per socket) and `create_unix_server`
  (`unlink`, `bind`, `chmod`);
- turn `listen_socket`/`listen_event` into `listen_sockets` +
  `std::map<int, ev::io*> listen_events`; rebuild them on reload for
  port and host changes, re-`listen()` on backlog change only;
- **`handle_connect` uses `watcher.fd`**, not the member socket;
- read the peer with `sockaddr_storage` + `inet_ntop`, set
  `client_addr_t{ip, family}`, demote `::ffff:`, handle `AF_UNIX` (empty
  ip → XFF required).

**Test:**

```bash
# default: listen_host = *
ss -lntp | grep 31000                 # 0.0.0.0:31000 and [::]:31000
# explicit: listen_host = 0.0.0.0 ::
# unix:     listen_host = unix:/run/ocelot.sock
curl --unix-socket /run/ocelot.sock \
  -H "X-Forwarded-For: 2606:4700:4700::1111" \
  "http://localhost/announce?...&compact=1&event=started"
# reload with a changed listen_host: all sockets rebuilt, no crash
```

**Estimate:** 3-4 hours, ~150 lines.

---

**Part B — site (Gazelle, `PhoenixProj/pp`):** commits S1–S6. Concrete
file references are in §7.2; schema changes are Phinx migrations under
`db/migrations/`.

### Site commit S1: tracker client and API carry `track_ipv6`

**Files:** `app/Tracker.php`, `app/API/User.php`, `app/Manager/User.php`,
`app/UserCreator.php`, `app/User/AutoEnable.php`,
`sections/user/takemoderate.php`, `sections/register/index.php`,
`sections/upload/upload_handle.php`

**What:** add `track_ipv6` as a first-class parameter of
`update_tracker('update_user'|'add_user', ...)` and pass it from every
call site, validating `0|1`. On its own this lets moderators enable IPv6
per user without a site schema change.

**Test:** `update_user` with `track_ipv6=1` reaches the tracker.

**Estimate:** 2-3 hours.

### Site commit S2: `track_ipv6` profile preference

**Files:** Phinx migration adding `users_main.track_ipv6 TINYINT(1) NOT
NULL DEFAULT 0`; `sections/user/edit.php`, `sections/user/take_edit.php`,
`sections/user/takemoderate.php`

**What:** a checkbox ("Allow the tracker to broadcast your IPv6 address
to the swarm"), default off, saved to `users_main.track_ipv6` and pushed
to the tracker; moderators can change it.

**Test:** toggling the checkbox changes the column and pushes to the
tracker.

**Estimate:** 2-3 hours.

### Site commit S3: `ips` table with CIDR ranges

**Files:** Phinx migrations creating `ips` and adding
`users_history_ips.IPID`; `app/Manager/IPv4.php` (or an IPv6-aware
replacement); `lib/config.php` (`IP_REGEXP`); `app/User.php`,
`app/UserCreator.php`, `app/API/User.php`

**What:** create `ips` (`StartAddress`/`EndAddress VARBINARY(16)`,
`Banned`, `BannedUntil`, `Bans`, `Reason`, `LastUserID`, `ActingUserID`,
unique `(StartAddress,EndAddress)`), add `users_history_ips.IPID` and
backfill it from the legacy text `IP`, move IP writes to the new model,
and make `validate_ip()` IPv6-aware.

**Test:** a new `/24` and a new `/64` round-trip through the repository.

**Estimate:** 1-2 days.

### Site commit S4: bans and anti-cheat on `ips`

**Files:** `app/Manager/IPv4.php`, `app/Search/IPv4.php`,
`sections/tools/misc/dupe_ip.php`, `sections/tools/managers/*ip*`,
`sections/user/advancedsearch.php`

**What:** replace `ip_bans.FromIP/ToIP` integers with `ips` ranges;
`dupe_ip` groups `users_history_ips` by `IPID`; IP search and advanced
search compare binary ranges with `INET6_ATON`/`INET6_NTOA`.

**Test:** a v6 ban blocks the range; dupe detection works across
families.

**Estimate:** 1-2 days.

### Site commit S5: read tracker addresses as IPv6-aware

**Files:** `app/Torrent.php` (`seederList`), `app/User.php`,
`app/Search/IPv4.php`, `sections/user/advancedsearch.php`,
`app/User/Torrents.php`

**What:** `IF(xu.ipv6 = '', INET6_NTOA(xu.ipv4), INET6_NTOA(xu.ipv6))`
for peer display plus `xu.port`, and the same over `xbt_snatched`.

**Test:** an IPv6-only peer shows its v6 address and port.

**Estimate:** 4-6 hours.

### Site commit S6: drop `user_seedbox`, add `users_connectable_status`

**Files:** Phinx migration dropping `user_seedbox` and creating
`users_connectable_status`; delete `app/User/Seedbox.php`,
`sections/user/seedbox_edit.php`, `sections/user/seedbox_view.php`;
`app/Torrent.php`, `app/User/Seedbox.php` call sites; a connectability
checker page + schedule task

**What:** remove the seedbox feature and its joins
(`xfu.ip = inet_ntoa(sx.ipaddr)`); connectability becomes
`users_connectable_status` (`UserID`, `IP VARCHAR(45)`, `IPID`,
`Status ENUM('no','yes','unset')`, `Time`), seeded periodically from
`xbt_files_users` and updated by the checker with
`ON DUPLICATE KEY UPDATE`. This consumes the tracker's new `port`
column.

**Test:** the connectability checker reports yes/no for v4 and v6 peers.

**Estimate:** 1-2 days.

### Sequencing across the two repositories

| Step | Tracker | Site | Gate |
|---|---|---|---|
| 1 | Commits 1–7 merged, `enable_ipv6 = false` | — | tracker tests pass |
| 2 | stage-1 migration applied (writes `ip` **and** `ipv4`/`ipv6`/`port`) | S1–S2 | no site breakage |
| 3 | `enable_ipv6 = true`, canary then all | S5 | `peers6` served |
| 4 | — | S3–S4, S6 | site fully on binary |
| 5 | stage 2: stop writing `ip`, then drop it | — | every site query on binary |

Steps 1–2 are purely additive and reversible. Step 5 is the only
destructive one and happens last.

---

## 6. Schema migration

The tracker schema lives in `gazelle.sql` + `migrations/` here (§6.1,
§6.2). The site schema is managed by Phinx in the Gazelle repository
(`db/migrations/`) and belongs to Part B / §7.

### 6.1 `gazelle.sql` (fresh installs)

Update the schema dump in place:

```sql
-- xbt_files_users (legacy `ip` kept during the staged migration)
`ip`   varchar(15) NOT NULL DEFAULT '',
`ipv4` varbinary(4)  DEFAULT NULL,
`ipv6` varbinary(16) DEFAULT NULL,
`port` int(6) NOT NULL DEFAULT 0,
-- xbt_snatched (legacy `IP` kept during the staged migration; D20 PK)
`IP`   varchar(15) NOT NULL,
`ipv4` varbinary(4)  DEFAULT NULL,
`ipv6` varbinary(16) DEFAULT NULL,
PRIMARY KEY (`uid`, `fid`),
-- users_main
`track_ipv6` tinyint(1) NOT NULL DEFAULT 0,
```

No new index (§4.4).

### 6.2 `migrations/2026-10-08-add-ipv6.sql` (existing installs)

The repo has no `migrations/` directory yet; this commit creates it.
Adjust the date to the actual merge date. Idempotent: MySQL 8 has no
`ADD COLUMN IF NOT EXISTS` (MariaDB-only), so use the
`information_schema` + prepared-statement pattern.

```sql
-- Idempotent IPv6 migration (adds binary columns, keeps legacy text)

-- xbt_files_users.ipv4
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_files_users'
    AND COLUMN_NAME = 'ipv4');
SET @s = IF(@c = 0,
  'ALTER TABLE xbt_files_users ADD COLUMN ipv4 VARBINARY(4) DEFAULT NULL',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- xbt_files_users.ipv6
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_files_users'
    AND COLUMN_NAME = 'ipv6');
SET @s = IF(@c = 0,
  'ALTER TABLE xbt_files_users ADD COLUMN ipv6 VARBINARY(16) DEFAULT NULL',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- xbt_files_users.port
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_files_users'
    AND COLUMN_NAME = 'port');
SET @s = IF(@c = 0,
  'ALTER TABLE xbt_files_users ADD COLUMN port INT(6) NOT NULL DEFAULT 0',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- xbt_snatched.ipv4
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_snatched'
    AND COLUMN_NAME = 'ipv4');
SET @s = IF(@c = 0,
  'ALTER TABLE xbt_snatched ADD COLUMN ipv4 VARBINARY(4) DEFAULT NULL',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- xbt_snatched.ipv6
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_snatched'
    AND COLUMN_NAME = 'ipv6');
SET @s = IF(@c = 0,
  'ALTER TABLE xbt_snatched ADD COLUMN ipv6 VARBINARY(16) DEFAULT NULL',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- users_main.track_ipv6
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users_main'
    AND COLUMN_NAME = 'track_ipv6');
SET @s = IF(@c = 0,
  'ALTER TABLE users_main ADD COLUMN track_ipv6 TINYINT(1) NOT NULL DEFAULT 0',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- Backfill the binary IPv4 from the legacy text (stage 1)
UPDATE xbt_files_users SET ipv4 = INET6_ATON(ip)
 WHERE ipv4 IS NULL AND ip <> '' AND INET6_ATON(ip) IS NOT NULL;
UPDATE xbt_snatched SET ipv4 = INET6_ATON(IP)
 WHERE ipv4 IS NULL AND IP <> '' AND INET6_ATON(IP) IS NOT NULL;

-- D20: xbt_snatched becomes unique per (uid, fid).
-- Guard: once the target PK exists (PRIMARY contains `fid`), skip it all.
SET @done = (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_snatched'
    AND INDEX_NAME = 'PRIMARY' AND COLUMN_NAME = 'fid');

-- 1. temporary auto-increment PK: deterministic "keep the newest" rule
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_snatched'
    AND COLUMN_NAME = 'snatch_id');
SET @s = IF(@done = 0 AND @c = 0,
  'ALTER TABLE xbt_snatched ADD COLUMN snatch_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- refresh the column existence after step 1
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_snatched'
    AND COLUMN_NAME = 'snatch_id');

-- 2. keep only the newest row per (uid, fid); no ties can survive
SET @s = IF(@done = 0 AND @c = 1,
  'DELETE s FROM xbt_snatched s JOIN (SELECT uid, fid, MAX(snatch_id) AS keep FROM xbt_snatched GROUP BY uid, fid) k ON k.uid = s.uid AND k.fid = s.fid AND s.snatch_id < k.keep',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- 3. swap the temporary PK for the real one
SET @s = IF(@done = 0 AND @c = 1,
  'ALTER TABLE xbt_snatched DROP PRIMARY KEY, DROP COLUMN snatch_id, ADD PRIMARY KEY (uid, fid)',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
```

Impact: the three `xbt_files_users` `ALTER`s are fast on MySQL 8
(INPLACE); `xbt_snatched` and `users_main` are instant. The two backfill
`UPDATE`s touch every row with a legacy `ip` and must be batched on very
large tables. No downtime required, but a maintenance window is
preferable.

### 6.3 Migration strategy: staged, like Empornium

Empornium's site (Luminance) did this in two stages: `v0.5.2` **added**
`ipv4 varbinary(4)`, `ipv6 varbinary(16)`, `port` and `ctime` to
`xbt_files_users` while **keeping** the legacy `ip varchar(15)`, and
switched its queries to `INET6_NTOA(...)`; `v0.6.0` only then dropped
`ip`. The tracker (Radiance v1.1) had already started writing the binary
columns.

We follow the same staging:

- **Stage 1 (this feature).** Add `ipv4`, `ipv6`, `port` alongside `ip`;
  the tracker writes **both** the textual `ip` and the binary
  `ipv4`/`ipv6`, so today's site keeps working unchanged; the migration
  backfills `ipv4` from `ip` and deduplicates `xbt_snatched` into a
  `(uid, fid)` primary key (D20, §6.2); the site then migrates to
  `INET6_NTOA(ipv4)` / `INET6_NTOA(ipv6)` and to the §7 model at its own
  pace.
- **Stage 2 (separate change, after the site is on binary).** Stop
  writing `ip`, then drop the column, exactly as Luminance `v0.6.0`.

Stage 2 is out of scope here but is an explicit, planned follow-up.
Because stage 1 writes both representations, the site migration is not
blocking: the tracker can be enabled first.

---

## 7. Site integration (Gazelle) contract

Decided as **N1 = (A)**, **N2 = drop `user_seedbox`**, **N3 = implement**,
**N4 = coordinated tracker + site, staged** — the Empornium model. This
work lives in the Gazelle repository (`PhoenixProj/pp`), not
here; the tracker only has to produce the columns below.

### 7.1 Tracker-side guarantees (this repository)

- `xbt_files_users.ipv4`/`ipv6` are 4/16 raw bytes, network order; `port`
  is the announced port; the legacy `ip` is still written in stage 1.
- `xbt_snatched.ipv4`/`ipv6` likewise; the table is unique per
  `(uid, fid)` (D20), so snatch history returns one row per
  user/torrent.
- `users_main.track_ipv6` is the opt-in flag; a peer whose owner has not
  opted in is never recorded on IPv6 and its IPv6 is never offered in
  `peers6`.

### 7.2 Site work, modelled on Luminance

1. **IP identity: an `ips` table with CIDR ranges.** `StartAddress` /
   `EndAddress VARBINARY(16)`, unique key `(StartAddress, EndAddress)`,
   lookups with `INET6_ATON(?)`. `users_history_ips` keeps
   `UserID`/`StartTime`/`EndTime` but points at the range via `IPID`
   instead of storing a text address.
2. **Bans live in `ips`.** `Banned`, `BannedUntil`, `Bans`, `Reason`;
   public-range-only validation; matching with `StartAddress <= ? AND
   EndAddress >= ?`. This replaces `ip_bans.FromIP/ToIP` integers.
3. **Drop `user_seedbox` and the seedbox joins.** Connectability becomes
   `users_connectable_status` (`UserID`, `IP VARCHAR(45)`, `IPID`,
   `Status ENUM('no','yes','unset')`, `Time`): a periodic job seeds it
   from `xbt_files_users`, taking the IPv6 address when present and the
   IPv4 otherwise (`IF(ipv6 = '', INET6_NTOA(ipv4), INET6_NTOA(ipv6))`),
   and the checker writes results with `ON DUPLICATE KEY UPDATE`. This
   removes `user_seedbox`,
   `app/User/Seedbox.php`, the `xfu.ip = inet_ntoa(sx.ipaddr)` joins
   (`app/Torrent.php:402`, `app/User/Seedbox.php:87,99`) and the
   `s.addr_a = xfu.IP` join in `app/Search/IPv4.php`.
4. **Read addresses with `INET6_NTOA`, preferring IPv6.** Peer list:
   `IF(xu.ipv6 = '', INET6_NTOA(xu.ipv4), INET6_NTOA(xu.ipv6))` plus
   `xu.port`; IP tracker history the same over `xbt_snatched`; user peer
   list `INET6_NTOA(ipv4)`.
5. **`track_ipv6` as a profile preference**, pushed with
   `update_user&passkey=...&track_ipv6=0|1` and settable by moderators.
6. **IPv6-aware validation:** `filter_var(..., FILTER_VALIDATE_IP,
   FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)`.
7. **Dual-stack display:** a dual-stack peer is one row with both `ipv4`
   and `ipv6`; assume neither is always present.

### 7.3 Sequencing

Stage 1 (§6.3) ships with the tracker writing both representations, so the
site migration is not blocking `enable_ipv6`. The `user_seedbox` removal
and the `ips`/CIDR move are a site project that must land before stage 2
drops `ip`, but not before the flag is enabled.

Prerequisite outside both repositories: the tracker host must have IPv6
connectivity and, when a proxy sits in front, the proxy must listen on
IPv6 and forward `X-Forwarded-For` with v6 addresses. Otherwise `peers6`
is never populated in production, however correct the code is.

---

## 8. Testing

### 8.1 Unit tests

- `ipv4_is_public` / `ipv6_is_public` over every range of §4.3, in
  particular `fd00::1` (private), `fc00::1` (private), `fe80::1`,
  `::1`, `2001:db8::1`, `2002::1`, `3ffe::1`, and accepted
  `2606:4700:4700::1111`, `8.8.8.8`.

### 8.2 Manual functional tests

Use a **public** IPv6 (e.g. `2606:4700:4700::1111`): `2001:db8::1` is a
documentation prefix and is rejected by `ipv6_is_public` by design.

```bash
# Test 1: IPv4 must keep working
curl -4 "http://127.0.0.1:31000/announce?info_hash=%aa%bb%cc%dd&peer_id=-OC0001-123456789012&port=6881&uploaded=0&downloaded=0&left=0&compact=1&event=started" \
  -H "X-Forwarded-For: 203.0.113.50"        # 203.0.113.0/24 is not in the reject list
# Expected: success

# Test 2: IPv6 in XFF, enable_ipv6=true
curl "http://127.0.0.1:31000/announce?info_hash=%aa%bb%cc%dd&peer_id=-OC0001-123456789012&port=6881&uploaded=0&downloaded=0&left=0&compact=1&event=started" \
  -H "X-Forwarded-For: 2606:4700:4700::1111"
# Expected: success; peers6 present (needs commit 6)

# Test 3: garbage in XFF
curl "http://127.0.0.1:31000/announce?info_hash=%aa%bb%cc%dd&peer_id=-OC0001-123456789012&port=6881&uploaded=0&downloaded=0&left=0&compact=1&event=started" \
  -H "X-Forwarded-For: not-an-ip"
# Expected: warning, peer registered with the socket IP (127.0.0.1)

# Test 4: IPv6 in XFF with enable_ipv6=false
# Expected: clear client error "IPv6 tracking is disabled", no fatal

# Test 5: direct connection over IPv6 (needs commit 7)
ss -lntp | grep 31000                      # both 0.0.0.0:31000 and [::]:31000
curl -g "http://[::1]:31000/announce?...&compact=1&event=started"
# Expected: bencoded response, not connection refused. ::1 is private, so
# use XFF with a routable IPv6 to see the peer actually recorded.
```

### 8.3 Integration tests

- qBittorrent/Deluge over IPv6-only: completes an announce, sees IPv6
  peers, downloads from them.
- Dual-stack client announcing the same `peer_id` over v4 and v6:
  `stats.leechers`/`seeders` and the row count reflect **one** peer;
  `get_count`/ratios are not doubled.
- `tcpdump -i lo -X 'tcp port 31000'`: the response really contains
  `peers6`.
- Listener: `listen_host = *`, `= 0.0.0.0 ::` and
  `= unix:/run/ocelot.sock` all start and serve; a reload that changes
  `listen_host` rebuilds every socket without dropping the loop; an
  announce accepted on the unix socket registers the XFF address, and is
  rejected with a clear error when XFF is missing.
- Snatch dedupe (D20): completing the same torrent twice leaves exactly
  one `xbt_snatched` row per `(uid, fid)`; the migration is idempotent
  when re-run.

### 8.4 IPv4 regression tests

- IPv4-only clients: stats, ratio and connectability identical to before.
- `stats.ipv6_peers == 0`; DB `ipv4` set (binary), `ipv6` NULL, and the
  legacy `ip` still written during stage 1.
- `ON DUPLICATE` change: a v4 peer changing address now has `ip`,
  `ipv4` and `port` updated; confirm this is acceptable to the site (it
  is the intended `5385c05` behaviour).

### 8.5 Feature-flag and opt-in tests

- `enable_ipv6=false` → behaviour as pre-feature.
- `enable_ipv6=true` → BEP 07 active.
- Flip true→false with a reload while running: v4 keeps working, v6
  announces get the clear error, no crash.
- `track_ipv6` 0→1 via `update_user`: the peer starts being recorded on
  IPv6 without a tracker restart.

---

## 9. Rollback

### 9.1 Code

Tracker: `git revert` commits 7 → 1, in reverse order, each atomic.
Site: revert S6 → S1 in `PhoenixProj/pp`. The two streams are
independent: reverting the site does not require reverting the tracker,
and vice versa, as long as stage 1 keeps writing both representations.

### 9.2 DB

```sql
ALTER TABLE xbt_files_users DROP COLUMN ipv4, DROP COLUMN ipv6, DROP COLUMN port;
ALTER TABLE users_main     DROP COLUMN track_ipv6;
ALTER TABLE xbt_snatched   DROP PRIMARY KEY, DROP COLUMN ipv4, DROP COLUMN ipv6;
```

The column drops are additive and lose no data. **D20 is the exception:**
the deduplicated `xbt_snatched` rows are gone, and removing the primary
key does not bring them back — take a table backup before the migration.
The legacy `ip`/`IP` text columns are untouched throughout stage 1.

### 9.3 Operational kill switch

```ini
enable_ipv6 = false
```

Reload. IPv4 is untouched; IPv6 users stop being tracked but do not
crash.

### 9.4 Rationale carried from `5385c05` (peer key)

The in-memory key is `xxh64(peer_id ‖ userid)`, family-independent. The
DB row is `(peer_id, fid, uid)`. Two peers of the same user on the same
torrent with the same `peer_id` collide, exactly as on IPv4 today. A
dual-stack client therefore occupies one entry holding both families; it
must not be split, or the seeders/leechers counts inflate again.

---

## 10. Decisions log

| # | Decision | Where |
|---|---|---|
| D1 | Parse with `getaddrinfo(AF_UNSPEC, AI_NUMERICHOST)`, success `== 0` | §4.1 |
| D2 | Binary addresses: add `ipv4 varbinary(4)`, `ipv6 varbinary(16)`, `port`; legacy `ip` kept in stage 1 | §4.4, §6.3 |
| D3 | No index on `ipv4`/`ipv6` (the site looks up via its own `ips` table) | §4.4 |
| D4 | One peer holds both families; no family discriminator in the key | §4.2, §9.4 |
| D5 | `track_ipv6` explicit opt-in, default 0, existing and new users | §4.5 |
| D6 | Add `ip=VALUES(ip),ipv4=VALUES(ipv4),ipv6=VALUES(ipv6),port=VALUES(port)` to `ON DUPLICATE KEY UPDATE` | §4.4 |
| D7 | `enable_ipv6` gates the worker, not the listener | §4.6 |
| D8 | `ipv6=`/`ipv4=`/`ip=` may fill only the non-connection family | §5 Commit 3 |
| D9 | Emit BEP 24 `external ip` (announcer's own address, v6 first) | §4.7 |
| D10 | Migration ships in `gazelle.sql` **and** `migrations/` | §6 |
| D11 | `ipv4_is_public`/`ipv6_is_public` live in `misc_functions`, portable byte tests, ULA `/7` | §4.3 |
| D12 | Listener adopts Radiance `7eef3e6`: `listen_host` (`*` / list / `unix:`), one socket per family, `IPV6_V6ONLY=1`, `watcher.fd` | §4.8 |
| D13 | Site contract: `track_ipv6` preference, `INET6_NTOA` reads, `ips`/CIDR model, `user_seedbox` dropped | §7 |
| D14 | `listen_host` config key (default `*`, space-separated, `unix:/path`) | §4.8 |
| D15 | Staged migration: stage 1 add binary + keep `ip`, stage 2 drop `ip` | §6.3 |
| D16 | N1: site IP model = binary/CIDR everywhere, as Luminance (`ips` table) | §4.4, §7.2 |
| D17 | N2: drop `user_seedbox`; connectability via `users_connectable_status` | §3, §7.2 |
| D18 | N3: implement IPv6 anti-cheat (bans, IP history, dupe IP, IP search) as Luminance | §7.2 |
| D19 | N4: coordinated tracker + site change, staged | §6.3, §7.3 |
| D20 | Deduplicate `xbt_snatched`, add `PRIMARY KEY (uid, fid)`, flush via `ON DUPLICATE KEY UPDATE` (aligns with Luminance; destructive, back up first) | §4.4, §6.2, §9.2 |

**No owner decisions remain.** D1–D20 are settled; the N1–N4 site work
(§7) is a scheduled follow-up in the Gazelle repository, not an open
question.

Known Radiance defects deliberately **not** copied:

- `inet_pton(...) != -1` accepts invalid strings (`worker.cpp:669-705`).
- ULA checked as `fc00::/16`, letting `fd00::/8` through.
- `s6_addr32`/`s6_addr16` portability.
- `hex_decode()` applied to announce IPs.

---

## 11. References

### Empornium reference repositories

| Repository | Role | Version / commit | Used for |
|---|---|---|---|
| https://github.com/Empornium/Radiance | Tracker, Ocelot fork | v1.1.6, `bd1829d` | Listener (§4.8), `peers6`/BEP 07, IPv6 recording, validation ranges, stats |
| https://github.com/Empornium/Luminance | Site, Gazelle fork | v0.6.0, `23b568c1` | Site IP model, `track_ipv6` API, `INET6_NTOA` reads, staged migration (§6.3) |

Radiance commits worth reading:

- `7eef3e6` "Full support for IPv6 interface and Unix sockets" —
  `listen_host`, one socket per family, `IPV6_V6ONLY=1`, `watcher.fd`,
  `sockaddr_storage`, `::ffff:` demotion (basis of §4.8 / Commit 7).
- `33ed67a` "Access to wrong variable with IP address" — the
  `getaddrinfo` bug this plan guards against (§4.1).
- `edd04bb` "Fix IP range for 169.254.0.0/16 check" — netmask bug
  (§4.3).
- `23f039c` "Allow to use custom HTTP header name instead of
  X-Forwarded-For" — `real_ip_header`, out of scope but noted.

Luminance releases:

- `v0.5.2` — adds `ipv4`/`ipv6`/`port`/`ctime`, keeps legacy `ip`,
  switches queries to `INET6_NTOA`.
- `v0.6.0` — drops the legacy `ip` column.

### Standards and other forks

- BEP 03: https://www.bittorrent.org/beps/bep_0003.html
- BEP 07 (IPv6 Tracker Extension): https://www.bittorrent.org/beps/bep_0007.html
- BEP 24 (`external ip`): https://www.bittorrent.org/beps/bep_0024.html
- Our repositories (both on branch `feature/ipv6`):
  - tracker: `git@github.com:PhoenixProj/Ocelot.git` — upstream remote.
    The historical `upstream/ipv6` attempt lives on this remote.
  - site: `git@github.com:PhoenixProj/pp.git`.
- OPSnet/Ocelot issue #6 (historical upstream of PhoenixProj/Ocelot,
  origin of the feature): https://github.com/OPSnet/Ocelot/issues/6
- wuubi/Ocelot (range-check logic): https://github.com/wuubi/Ocelot/blob/master/src/worker.cpp

---

## 12. Total estimate

| Phase | Estimate |
|---|---|
| Commit 1 (config + validation helpers) | 1 hour |
| Commit 2 (address plumbing + XFF) | 1.5 hours |
| Commit 3 (BEP 07 ip params) | 1 hour |
| Commit 4 (peer struct) | 1 hour |
| Commit 5 (dual-stack + recording + stats) | 4-5 hours |
| Commit 6 (BEP 07 peers6 + external ip) | 2 hours |
| Commit 7 (listener: dual-stack, `listen_host`, unix) | 3-4 hours |
| Migration SQL + `gazelle.sql` (tracker) | 30 min |
| Test and debug (tracker) | 3-4 hours |
| **Tracker total (this repository)** | **~3 working days** |
| Site S1–S2 (client + preference) | 4-6 hours |
| Site S3–S4 (`ips`/CIDR + anti-cheat) | 2-4 days |
| Site S5 (IPv6-aware reads) | 4-6 hours |
| Site S6 (drop seedbox, connectability) | 1-2 days |
| Site test and migration | 1-2 days |
| **Site total (Gazelle repository)** | **~1.5-2 weeks** |
| **Combined** | **~2-2.5 weeks** |

---

## 13. Final notes

- The commits are **independent**. Stopping at commit 2 already fixes
  the current bug for proxy deployments; commit 7 is only needed for
  direct IPv6 connections, explicit binds and unix sockets.
- Listener choices follow Radiance `7eef3e6`, including `watcher.fd` in
  `handle_connect` and the staged migration of §6.3.
- N1–N4 are decided as D16–D19, the Empornium model: binary/CIDR IPs,
  `user_seedbox` dropped, IPv6 anti-cheat implemented, coordinated and
  staged tracker + site change. D20 adds the `xbt_snatched` dedupe.
- `enable_ipv6 = false` by default makes rollout safe: switch it on
  after testing, off if anything breaks.
- The site-side changes (§7) are needed for goal 3 but are not blocking:
  stage 1 writes both representations, so the tracker can be enabled
  first and the site can follow.
- The plan covers two repositories and both must be reviewed together:
  tracker (`PhoenixProj/Ocelot`) and site (`PhoenixProj/pp`). The
  upstream PR targets `PhoenixProj/Ocelot`; the site change is a normal
  PR to `PhoenixProj/pp`.
- All tracker-side code must follow the current fork's style
  (`fmt::format`, typed `record_peer`, `xxhash`, const-correctness), not
  Radiance's.
- Housekeeping on merge: add a `CHANGES` entry (FEATURES: IPv6 tracking,
  BEP 07 `peers6`, `enable_ipv6` / `track_ipv6`) and bump the stale
  `CMakeLists.txt` version.
