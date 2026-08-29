# Plan: IPv6 support in Ocelot

Status: draft
Owner: @orphelus
Upstream reference: https://github.com/OPSnet/Ocelot/issues/6
Working branch: `feature/ipv6`
Upstream PR: TBD (open when the branch is tested)

---

## 1. Context

Ocelot on `master` (3.1.0) parses the `X-Forwarded-For` header with
`inet_pton(AF_INET, ...)` and therefore only accepts IPv4. The consequences:

> Note: `CHANGES` records 3.1.0 released 2026-04-13, but `CMakeLists.txt`
> still declares `VERSION 3.0.0` (stale). Bump it separately from this
> feature.

- A client on an IPv6-only connection (increasingly common on Italian
  residential ISPs like TIM/Vodafone/Fastweb and on virtually all modern
  VPSes) gets the error `failed to parse X-Forwarded-For: <hex>` and
  cannot announce.
- The `peer` struct stores the IP as `uint32_t` in `addr_port::addr`,
  4 bytes, insufficient for IPv6.
- The compact response only contains `peers` (BEP 03), not `peers6` (BEP 07).

There is an `upstream/ipv6` branch (commit `4e7e250`, 2018 — identical to
wuubi's `ipv6` branch) that attempts the support, but it is **not a usable
base**. Verified against the branch source:

- it does not compile against the current dependency set: `ocelot.cpp`
  uses the removed spdlog `_st` sink API (`stdout_sink_st`,
  `daily_file_sink_st`), no longer present in the spdlog 1.15 vendored
  in master, and it is still on the autotools codebase (no CMake);
- in the X-Forwarded-For branch it calls `getaddrinfo(ip.c_str(), ...)`
  instead of `getaddrinfo(ip_tmp.c_str(), ...)`: it compiles, but parses
  the socket IP and silently discards the header value;
- `private_ipv6()` ends with `|| true`, so it always returns true and
  the worker clears **every** IPv6 (`misc_functions.cpp:197-198`);
- it applies `hex_decode()` to the announce IPs (`worker.cpp:514, 530`);
- `record_peer` still takes a raw pre-formatted SQL record string,
  incompatible with the typed signature of current master.

There is a `wuubi/Ocelot` fork (branch `master`, commit `fac0fd1`) with
a working BEP 07 implementation, but structurally older than our fork
(no `xxhash`, no `fmt::format`, `record_peer` taking raw strings).
Merging it would regress years of work.

**Decision:** implement IPv6 on our codebase, taking from wuubi **only
the logic** for IP detection/validation (~80 lines), not the code.

---

## 2. Goals

1. Ocelot correctly accepts and processes announces from IPv6-only clients.
2. The compact response includes `peers6` per BEP 07 when the announcer is IPv6.
3. IPv6 addresses are persisted in `xbt_files_users.ipv6` and used for
   connectability and anti-cheat the same way IPv4 addresses are.
4. IPv4 behavior unchanged (zero regressions).
5. Feature flag `enable_ipv6 = false` by default, explicit opt-in.

## 3. Non-goals

- IPv6 multicast or anycast (BEP 07 defines them, BEP 03 does not use them, out of scope).
- Cloudflare/CDN logic replacement.
- Modifying the current wire format of `peers` (stays 6 bytes/peer).
- `compact=0` support for IPv6 (modern clients use `compact=1`).
- Refactoring `record_peer` or other changes not strictly required.

---

## 4. Architectural decisions

### 4.1 IP detection: `getaddrinfo` with `AF_UNSPEC` and `AI_NUMERICHOST`

Replaces the current `inet_pton(AF_INET, ...)` on `X-Forwarded-For` and
on the BEP 03 `ip=` parameter. `getaddrinfo` with `AI_NUMERICHOST` parses
both v4 and v6, does not do DNS, and is strictly numeric (no spoofing
like `1.2.3.4 evil.com`).

```cpp
struct addrinfo hint{}, *res = nullptr;
hint.ai_family = AF_UNSPEC;
hint.ai_flags = AI_NUMERICHOST;
if (getaddrinfo(ip.c_str(), nullptr, &hint, &res) == 0) {
    if (res->ai_family == AF_INET)      ipv4 = ip;
    else if (res->ai_family == AF_INET6) ipv6 = ip;
    freeaddrinfo(res);
}
```

Return code check: if `getaddrinfo` fails, the header is garbage and
is silently dropped (warning log, no fatal error).

### 4.2 Peer storage: separate IPv6 field

The current `peer` struct uses `addr_port { uint32_t addr; uint16_t port; }`
= 6 bytes, BEP 03 format. For IPv6 we need 16 bytes address + 2 bytes port
= 18 bytes (BEP 07).

We do not touch `addr_port` (IPv4 stays intact). We add:

```cpp
class peer {
  public:
    user_ptr user;
    addr_port ap;             // IPv4, 6 compact bytes (unchanged)
    std::string ipv6;         // IPv6 in textual notation, 16+ chars
    std::string ipv6_port;    // 18 compact bytes (16 addr + 2 port)
    // ... rest unchanged
};
```

`std::string` for IPv6 is less efficient than `in6_addr` but simpler
and keeps symmetry with how wuubi handles IPs. Profile later if it
becomes a bottleneck.

### 4.3 Public/private validation: new functions in `misc_functions`

```cpp
bool ipv4_is_public(in_addr addr);   // 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, 127/8
bool ipv6_is_public(in6_addr addr);  // ::1/128, fe80::/10, fc00::/7, fec0::/16, 3ffe::/16, 2001:db8::/32, 2001::/32, 2002::/16
```

Copied from wuubi, already correct. Add them to `misc_functions.h` and
the corresponding `.cpp`. `is_development()` shortcut for tests.

### 4.4 DB schema: new `ipv6` column

Add `ipv6 VARBINARY(16) DEFAULT NULL` to `xbt_files_users` (16 exact
bytes for `in6_addr`). Secondary index for queries.

The same column is added to `xbt_snatched` (see §6.2): Commit 5 extends
`record_snatch` to store the announce IPv6 next to the IPv4, mirroring
what the WhatCD-era forks do (`xbt_snatched.IP, ipv6`).

Idempotent migration, no downtime (Gazelle accepts `ALTER TABLE` on
`xbt_files_users` while hot, but a maintenance window is preferable).

**We do not remove** the existing `ipv4` column: IPv4-only clients keep
using it. `ipv4` and `ipv6` are mutually exclusive per peer (a peer is
either v4 or v6, not both).

### 4.5 Per-user opt-in: `track_ipv6`

Extend `users_main` with `track_ipv6 TINYINT(1) DEFAULT 0`. Default 0:
existing users are not tracked on IPv6 until they explicitly opt in
(via `update_user track_ipv6=1` through the API). Safety belt: no IPv6
ends up in clear in the DB without consent.

Worker side:

```cpp
if (!u->track_ipv6()) ipv6.clear();
```

### 4.6 Global feature flag: `enable_ipv6 = false`

Default off. When `false`, the worker does exactly what it does today:
accepts only IPv4, silently discards everything else. When `true`, it
activates detection/validation/storage/BEP 07 response.

This gives the operator an immediate kill switch if something goes wrong.

### 4.7 Wire format: additive `peers6`

When `p->ipv6` is not empty and the remote peer (`u->track_ipv6()`) has
opted in, include `peers6` in the response:

```
d8:intervali1800e5:peers6:<18*N bytes>e6:peers6:<18*N bytes>e
```

The 18 bytes per peer are 16 bytes of `in6_addr` (network byte order)
+ 2 bytes of `port` (network byte order). Clients that do not support
BEP 07 silently ignore the `peers6` key.

---

## 5. Roadmap commit-by-commit

6 atomic commits, each compilable and testable.

### Commit 1: `misc: add ipv4_is_public and ipv6_is_public`

**Files touched:** `src/misc_functions.h`, `src/misc_functions.cpp`

**What:** Add the two validation functions, taken from wuubi.
Need to include `<arpa/inet.h>` and `<netdb.h>` in `misc_functions.h`.

**Test:** inline unit test (assertions in a test main, or a simple
`assert(ipv4_is_public(...))`).

**Estimate:** 30 min, ~30 lines.

### Commit 2: `worker: use getaddrinfo for X-Forwarded-For parsing`

**Files touched:** `src/worker.cpp`

**What:** Replace the `inet_pton(AF_INET, ...)` block on XFF with
`getaddrinfo(AF_UNSPEC, AI_NUMERICHOST)`. It does not yet do anything
with IPv6 except accept it into `ipv4` if it is a valid v4. On its own,
this commit fixes the minimal use case.

**Test:** tcpdump on port 31000, verify:
- IPv4 in XFF -> works as before
- IPv6 in XFF -> logs a warning but no fatal error
- Garbage in XFF -> silently discarded

**Estimate:** 1 hour, ~25 lines changed.

### Commit 3: `worker: accept IPv6 from ip= and ipv4=/ipv6= params`

**Files touched:** `src/worker.cpp`

**What:** Add IP reading from the BEP 03 parameters (`ip`, `ipv4`,
`ipv6`) with the same `getaddrinfo` logic. Important for clients that
pass the IP explicitly instead of using XFF.

**Test:** curl with `?ip=2001:db8::1&...` must be accepted.

**Estimate:** 1 hour, ~20 lines.

### Commit 4: `peer: add ipv6 and ipv6_port fields`

**Files touched:** `src/peer.h`

**What:** Add `std::string ipv6` and `std::string ipv6_port` to the
`peer` struct. Initialized to `""` and `""`. No logic uses them yet.

**Test:** compile, existing behavior must keep working.

**Estimate:** 15 min, ~3 lines.

### Commit 5: `worker: dual-stack validation and IPv6 recording`

**Files touched:** `src/worker.cpp`, `src/db.h`, `src/db.cpp`,
`src/stats.h`, `src/user.h`, `src/ocelot.h`

**Commit 5 (worker/db):**
- `ipv4_is_public` / `ipv6_is_public` validation on both IPs
- Update `stats` with `ipv4_peers` and `ipv6_peers` (atomic)
- Add `bool track_ipv6` to `user` with getter/setter
- Extend `db::record_peer` and `db::record_snatch` with
  `const std::string &ipv4, const std::string &ipv6`
- Extend the flush SQL to write `ip, ipv6` on `xbt_files_users` and
  `IP, ipv6` on `xbt_snatched`
- Update the worker to pass ipv4/ipv6 to `record_peer` and `record_snatch`
- Filter `if (!u->track_ipv6()) ipv6.clear()` after validation
- Add `enable_ipv6 = false` check at the top of `worker::work`

**Test:**
- IPv4-only client: no regression (all `ipv6_*` counters stay 0)
- IPv6-only client with `track_ipv6=1`: `ipv6_peers` counter grows, DB has ipv6 set
- IPv6 client with `track_ipv6=0`: counter grows but DB has ipv6 NULL

**Estimate:** 3-4 hours, ~80 lines.

### Commit 6: `worker: emit BEP 07 peers6 in compact response`

**Files touched:** `src/worker.cpp`

**What:** Add the generation of `peers6` (18 bytes/peer) and the
inclusion in the bencode response when the announcer is IPv6.

**Test:** qBittorrent or Deluge (BEP 07 support) on IPv6-only must see
IPv6 peers in the list and download from them. rtorrent 0.9.8 (no BEP 07)
must keep working.

**Estimate:** 2 hours, ~40 lines.

---

## 6. Schema migration

### 6.1 `xbt_files_users`

```sql
ALTER TABLE xbt_files_users
  ADD COLUMN ipv6 VARBINARY(16) DEFAULT NULL,
  ADD INDEX idx_ipv6 (ipv6);
```

Impact: ~1 minute on a table with millions of rows (INPLACE ALTER in MySQL 8).

### 6.2 `xbt_snatched`

```sql
ALTER TABLE xbt_snatched
  ADD COLUMN ipv6 VARBINARY(16) DEFAULT NULL;
```

Required: Commit 5 extends `record_snatch` to persist the IPv6 alongside
the IPv4, and the current table has only `IP varchar(15)`
(`gazelle.sql:165-174`). Without this column the snatched flush fails
with *unknown column*.

Impact: instant.

### 6.3 `users_main`

```sql
ALTER TABLE users_main
  ADD COLUMN track_ipv6 TINYINT(1) NOT NULL DEFAULT 0;
```

Impact: instant.

### 6.4 Migration script

`migrations/2026-XX-XX-ipv6.sql` (adjust the date), idempotent:

```sql
-- Idempotent migration to IPv6 support
SET @col_exists = (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'xbt_files_users'
    AND COLUMN_NAME = 'ipv6'
);
SET @sql = IF(@col_exists = 0,
  'ALTER TABLE xbt_files_users ADD COLUMN ipv6 VARBINARY(16) DEFAULT NULL',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Idempotent index as well
SET @idx_exists = (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'xbt_files_users'
    AND INDEX_NAME = 'idx_ipv6'
);
SET @sql = IF(@idx_exists = 0,
  'ALTER TABLE xbt_files_users ADD INDEX idx_ipv6 (ipv6)',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'xbt_snatched'
    AND COLUMN_NAME = 'ipv6'
);
SET @sql = IF(@col_exists = 0,
  'ALTER TABLE xbt_snatched ADD COLUMN ipv6 VARBINARY(16) DEFAULT NULL',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users_main'
    AND COLUMN_NAME = 'track_ipv6'
);
SET @sql = IF(@col_exists = 0,
  'ALTER TABLE users_main ADD COLUMN track_ipv6 TINYINT(1) NOT NULL DEFAULT 0',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
```

(`ADD COLUMN IF NOT EXISTS` is MariaDB-only; MySQL 8 does not support it,
so every statement uses the `information_schema` + prepared-statement
pattern. Put this in `gazelle.sql` or in `contrib/` if it exists.)

---

## 7. Testing

### 7.1 Manual functional tests

Before merging to master:

```bash
# Test 1: IPv4 must keep working
curl -4 "http://127.0.0.1:31000/announce?info_hash=%aa%bb%cc%dd&peer_id=-OC0001-123456789012&port=6881&uploaded=0&downloaded=0&left=0&compact=1&event=started" \
  -H "X-Forwarded-For: 203.0.113.50"
# Expected: success

# Test 2: IPv6 in XFF must be accepted
curl "http://127.0.0.1:31000/announce?info_hash=%aa%bb%cc%dd&peer_id=-OC0001-123456789012&port=6881&uploaded=0&downloaded=0&left=0&compact=1&event=started" \
  -H "X-Forwarded-For: 2001:db8::1"
# Expected: success (no failure reason).
# Note: up to Commit 3 the announce succeeds but the peer is still
# tracked IPv4-only (socket IP). `peers6` in the response and the ipv6
# column in the DB appear only with Commit 5/6 and enable_ipv6 = true.

# Test 3: Garbage in XFF must be discarded, not a fatal error
curl "http://127.0.0.1:31000/announce?info_hash=%aa%bb%cc%dd&peer_id=-OC0001-123456789012&port=6881&uploaded=0&downloaded=0&left=0&compact=1&event=started" \
  -H "X-Forwarded-For: not-an-ip"
# Expected: warning log, peer registered with socket IP (127.0.0.1)

# Test 4: BEP 07 peers6 in the response
curl "http://127.0.0.1:31000/announce?info_hash=%aa%bb%cc%dd&peer_id=-OC0001-123456789012&port=6881&uploaded=0&downloaded=0&left=0&compact=1&event=started" \
  -H "X-Forwarded-For: 2001:db8::1" | xxd | head
# Expected: "peers6" key present
```

### 7.2 Integration tests

- Start Ocelot with `enable_ipv6 = true`
- Connect with qBittorrent (BEP 07) over IPv6
- Verify other IPv6 peers show up in the list
- Verify with `tcpdump -i lo -X 'tcp port 31000'` that the request/response
  actually contains IPv6 addresses

### 7.3 IPv4 regression tests

- IPv4-only clients must have stats, ratio, connectability identical
  to before
- `stats.ipv6_peers` must stay 0
- DB: `ipv4` populated, `ipv6` NULL

### 7.4 Feature flag tests

- `enable_ipv6 = false` -> behavior identical to pre-IPv6
- `enable_ipv6 = true` -> BEP 07 active
- Flip to `false` while running -> everything goes back to v4-only,
  no crash

---

## 8. Rollback

### 8.1 Code rollback

Standard `git revert` of the 6 commits, in reverse order (6 -> 1).
Each commit is atomic, so `git revert <SHA>` one at a time.

### 8.2 DB rollback

```sql
-- The added columns are additive, drop is safe
ALTER TABLE xbt_files_users DROP INDEX idx_ipv6;
ALTER TABLE xbt_files_users DROP COLUMN ipv6;
ALTER TABLE xbt_snatched DROP COLUMN ipv6;
ALTER TABLE users_main DROP COLUMN track_ipv6;
```

No data lost (the columns are new). No existing application reads
`ipv6` if we revert before merging to master.

### 8.3 Operational rollback (kill switch)

If IPv6 causes trouble in production:

```ini
# ocelot.conf
enable_ipv6 = false
```

Restart Ocelot, behavior goes back to v4-only. Zero impact on IPv4
users, IPv6 users stop announcing (but do not crash either).

---

## 9. Open decisions

### 9.1 `track_ipv6` conversion timing

Decide whether to ask for `track_ipv6` as a user opt-in or to
pre-enable it for new users. Recommendation: explicit opt-in,
GDPR-friendly.

### 9.2 IPv6 storage in `xbt_files_users`: VARBINARY(16) or two BIGINTs?

- `VARBINARY(16)`: 16 bytes, natural ordering, `INET6_ATON` not
  available in MySQL but convertible with `HEX(ipv6)`
- Two `BIGINT`: 8+8=16 bytes, easier to debug, but double overhead

Recommendation: `VARBINARY(16)`. Document the conversion helper.

### 9.3 IPs visible to DB sysadmins

A Gazelle sysadmin with DB access can see IPv6 addresses in clear via
`HEX(ipv6)`. Is that acceptable? Usually yes (Gazelle's trust model),
but worth documenting.

### 9.4 Peer key with xxhash and IPv6

Verified in `worker.cpp:499-502`: the key is
`xxh64(peer_id ‖ addr_port[6 bytes] ‖ userid)`. Two consequences:

- A client that announces over both families with the same `peer_id`
  (standard BEP 07 behavior, e.g. qBittorrent) must produce **two
  distinct peers**, otherwise a single record would flip between the
  IPv4 and the IPv6 announce at every request. The key must therefore
  include an address-family discriminator (1 byte: 0 = v4, 1 = v6) in
  the hash input — add it in Commit 4/5, not as an afterthought.
- Two peers of the same user on the same torrent with the same
  `peer_id` **and** the same family still collide, exactly as on IPv4
  today: same behavior, no regression.

### 9.5 Cleanup of the existing `ipv6` branch

After creating `feature/ipv6`, the `upstream/ipv6` branch (4e7e250) is
just noise. Candidate for local removal, but it is a remote ref
(`upstream/ipv6`) so it cannot be removed directly. Leave it, it is
just history.

---

## 10. References

- BEP 03 (The BitTorrent Protocol Specification): https://www.bittorrent.org/beps/bep_0003.html
- BEP 07 (IPv6 Tracker Extension): https://www.bittorrent.org/beps/bep_0007.html
- OPSnet/Ocelot issue #6: https://github.com/OPSnet/Ocelot/issues/6
- wuubi/Ocelot master (logic reference): https://github.com/wuubi/Ocelot/blob/master/src/worker.cpp
- Radiance (other tracker, comparison): https://github.com/Artifas/Radiance

---

## 11. Total estimate

| Phase | Estimate |
|---|---|
| Commit 1 (validation helpers) | 30 min |
| Commit 2 (X-Forwarded-For fix) | 1 hour |
| Commit 3 (BEP 03 ip= params) | 1 hour |
| Commit 4 (peer struct) | 15 min |
| Commit 5 (dual-stack + recording) | 3-4 hours |
| Commit 6 (BEP 07 peers6) | 2 hours |
| Migration SQL (xbt_files_users, xbt_snatched, users_main) | 30 min |
| Test and debug | 2-3 hours |
| **Total** | **~1.5 working days** |

---

## 12. Final notes

- The 6 commits are **independent**: if you stop at commit 2, you
  already have the fix for the current bug.
- The feature flag `enable_ipv6 = false` by default makes the rollout
  safe: turn it on after testing, turn it off if something breaks.
- The upstream PR is contingent on merging to local master, not a
  replacement. Upstream may or may not accept it; in either case the
  local fork is functional.
- `wuubi/Ocelot` stays as the logic reference, but the final code
  must follow the style of our fork (typed `record_peer`, `xxhash`,
  `fmt::format`).
