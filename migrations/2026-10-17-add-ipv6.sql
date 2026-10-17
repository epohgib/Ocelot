-- Idempotent IPv6 migration (adds binary columns, keeps legacy text)

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
-- the columns are NOT NULL DEFAULT '' (D22).
UPDATE xbt_files_users SET ipv4 = INET6_ATON(ip)
 WHERE ipv4 = '' AND ip <> '' AND INET6_ATON(ip) IS NOT NULL;
UPDATE xbt_snatched SET ipv4 = INET6_ATON(IP)
 WHERE ipv4 = '' AND IP <> '' AND INET6_ATON(IP) IS NOT NULL;

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

-- 2. keep only the newest row per (uid, fid), so no ties can survive.
--    Multi-table DELETE has no LIMIT, and a labeled REPEAT loop is only
--    valid inside a stored program, so this is a single set-based
--    statement: the survivor per key is computed once and every older
--    duplicate goes in the same pass. On a very large snatch table this is
--    the heaviest statement of the migration (see the plan's Impact note).
SET @s = IF(@done = 0 AND @c = 1,
  'CREATE TEMPORARY TABLE xbt_snatched_keep AS SELECT uid, fid, MAX(snatch_id) AS keep FROM xbt_snatched GROUP BY uid, fid',
  'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @s = IF(@done = 0 AND @c = 1,
  'DELETE s FROM xbt_snatched s JOIN xbt_snatched_keep k ON k.uid = s.uid AND k.fid = s.fid WHERE s.snatch_id < k.keep',
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
