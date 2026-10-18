-- Idempotent IPv6 migration (adds binary columns, keeps legacy text)

-- PRE-FLIGHT counts (informational, not gates): read these three numbers
-- before proceeding. No abort — an anomalous row must not stop an
-- otherwise correct migration, and duplicates are expected. Cost is one
-- scan per count, acceptable once, in the maintenance window.
-- 1) textual addresses the backfill does not copy (a short IPv6 literal
--    or an unparseable value): they stay without a binary address until
--    the tracker re-announces them.
SELECT count(*) AS skipped_files_users FROM xbt_files_users
 WHERE ip <> '' AND (INET6_ATON(ip) IS NULL OR LENGTH(INET6_ATON(ip)) <> 4);
SELECT count(*) AS skipped_snatched FROM xbt_snatched
 WHERE IP <> '' AND (INET6_ATON(IP) IS NULL OR LENGTH(INET6_ATON(IP)) <> 4);
-- 2) duplicate (uid, fid) rows that D20 deletes: the one irreversible
--    step of this migration (see the plan's Impact note; back up first).
SELECT count(*) - count(DISTINCT uid, fid) AS duplicates_to_delete FROM xbt_snatched;

-- xbt_files_users.ipv4
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_files_users'
    AND COLUMN_NAME = 'ipv4');
SET @s = IF(@c = 0,
  'ALTER TABLE xbt_files_users ADD COLUMN ipv4 VARBINARY(4) NOT NULL DEFAULT ''''',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- xbt_files_users.ipv6
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_files_users'
    AND COLUMN_NAME = 'ipv6');
SET @s = IF(@c = 0,
  'ALTER TABLE xbt_files_users ADD COLUMN ipv6 VARBINARY(16) NOT NULL DEFAULT ''''',
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
  'ALTER TABLE xbt_snatched ADD COLUMN ipv4 VARBINARY(4) NOT NULL DEFAULT ''''',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- xbt_snatched.ipv6
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_snatched'
    AND COLUMN_NAME = 'ipv6');
SET @s = IF(@c = 0,
  'ALTER TABLE xbt_snatched ADD COLUMN ipv6 VARBINARY(16) NOT NULL DEFAULT ''''',
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

-- Backfill the binary IPv4 from the legacy text (stage 1).
-- The guard is the initially-empty value (`ipv4 = ''`), not IS NULL —
-- the columns are NOT NULL DEFAULT '' (D22). Only a 4 byte address
-- belongs in a varbinary(4): the text column can hold a short IPv6
-- literal, and INET6_ATON() of one is 16 bytes, so an IS NOT NULL guard
-- would abort the migration (ERROR 1406) on the assignment.
UPDATE xbt_files_users SET ipv4 = INET6_ATON(ip)
 WHERE ipv4 = '' AND ip <> '' AND LENGTH(INET6_ATON(ip)) = 4;
UPDATE xbt_snatched SET ipv4 = INET6_ATON(IP)
 WHERE ipv4 = '' AND IP <> '' AND LENGTH(INET6_ATON(IP)) = 4;

-- D20: xbt_snatched becomes unique per (uid, fid).
-- Guard: once the target PK exists (PRIMARY contains `fid`), skip it all.
SET @done = (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'xbt_snatched'
    AND INDEX_NAME = 'PRIMARY' AND COLUMN_NAME = 'fid');

-- 1. temporary auto-increment PK: the table has no primary key today, so this is
--    the only stable identity a row has while the survivors are chosen.
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

-- 2. keep only the row with the latest tstamp per (uid, fid); snatch_id
--    (the physical insertion order) only breaks a tstamp tie. tstamp is the
--    announce time and the column the site orders its history by, while
--    snatch_id follows the heap order of an INSERT IGNORE table that never
--    had a primary key.
--    Multi-table DELETE has no LIMIT, and a labeled REPEAT loop is only
--    valid inside a stored program, so this is a single set-based
--    statement: the survivor per key is computed once and every other
--    duplicate goes in the same pass. On a very large snatch table this is
--    the heaviest statement of the migration (see the plan's Impact note).
SET @s = IF(@done = 0 AND @c = 1,
  'CREATE TEMPORARY TABLE xbt_snatched_keep AS SELECT k.uid, k.fid, MAX(k.snatch_id) AS keep FROM xbt_snatched k JOIN (SELECT uid, fid, MAX(tstamp) AS latest FROM xbt_snatched GROUP BY uid, fid) t ON t.uid = k.uid AND t.fid = k.fid AND t.latest = k.tstamp GROUP BY k.uid, k.fid',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@done = 0 AND @c = 1,
  'DELETE s FROM xbt_snatched s JOIN xbt_snatched_keep k ON k.uid = s.uid AND k.fid = s.fid WHERE s.snatch_id <> k.keep',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
DROP TEMPORARY TABLE IF EXISTS xbt_snatched_keep;
-- NOTE: build the survivor table above with no snatch traffic in flight
-- (see Impact below); otherwise a duplicate written afterwards would
-- survive the migration. The step-3 PK swap then fails loudly on any
-- leftover duplicate, which is also the safety net.

-- 3. swap the temporary PK for the real one
SET @s = IF(@done = 0 AND @c = 1,
  'ALTER TABLE xbt_snatched DROP PRIMARY KEY, DROP COLUMN snatch_id, ADD PRIMARY KEY (uid, fid)',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
