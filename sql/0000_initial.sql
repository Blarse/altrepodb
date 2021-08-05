CREATE TABLE PackageSetName
(
    pkgset_uuid     UUID,
    pkgset_puuid    UUID,
    pkgset_ruuid    UUID,
    pkgset_depth    UInt8,
    pkgset_nodename String,
    pkgset_date     DateTime,
    pkgset_tag      String,
    pkgset_complete UInt8,
    pkgset_kv       Nested(k String, v String)
) ENGINE = MergeTree ORDER BY (pkgset_date, pkgset_nodename, pkgset_ruuid, pkgset_depth) PRIMARY KEY (pkgset_date, pkgset_nodename);

CREATE TABLE PackageSet
(
    pkgset_uuid     UUID,
    pkg_hash        UInt64
) ENGINE = ReplacingMergeTree ORDER BY (pkgset_uuid, pkg_hash) PRIMARY KEY (pkgset_uuid);

CREATE TABLE PackageSet_buffer AS PackageSet ENGINE = Buffer(currentDatabase(), PackageSet, 16, 10, 100, 10000, 1000000, 1000000, 10000000);


CREATE TABLE PackageHash
(
    pkgh_mmh        UInt64,
    pkgh_md5        FixedString(16),
    pkgh_sha1       FixedString(20),
    pkgh_sha256     FixedString(32)
) ENGINE ReplacingMergeTree ORDER BY (pkgh_mmh, pkgh_md5, pkgh_sha256) PRIMARY KEY pkgh_mmh;

CREATE TABLE PackageHash_buffer AS PackageHash ENGINE = Buffer(currentDatabase(), PackageHash, 16, 10, 100, 10000, 1000000, 1000000, 10000000);

CREATE 
OR REPLACE VIEW PackageHash_view AS
SELECT pkgh_mmh, lower(hex(pkgh_md5)) as pkgh_md5, lower(hex(pkgh_sha1)) as pkgh_sha1, lower(hex(pkgh_sha256)) as pkgh_sha256
FROM  PackageHash_buffer;


CREATE TABLE Tasks
(
    task_id             UInt32,
    subtask_id          UInt32, -- from listing gears/[1-7]*/userid
    task_repo           LowCardinality(String), -- from /task/repo
    task_owner          LowCardinality(String), -- from /task/owner
    task_changed        DateTime, -- from /task/state mtime
    subtask_changed     DateTime, -- from /gears/%subtask-id%/sid mtime
    subtask_deleted     UInt8, -- could find by /gears/%subtask_id%/{dir|srpm|package} directory contents
    subtask_userid      LowCardinality(String), -- from /geras/%subtask_id%/userid
    subtask_dir         String, -- from /geras/%subtask_id%/dir
    subtask_package     String, -- from /geras/%subtask_id%/package
    subtask_type        Enum8('unknown' = 0, 'srpm' = 1, 'gear' = 2, 'copy' = 3, 'delete' = 4, 'rebuild' = 5), -- from /geras/%subtask_id%/sid. WTF logic in girar-task-run check_copy_del()
    subtask_pkg_from    LowCardinality(String), -- from 'rebuild' or 'copy_repo' file
    subtask_sid         String, -- from /geras/%subtask_id%/sid
    subtask_tag_author  String, -- from /geras/%subtask_id%/tag_author
    subtask_tag_id      String, -- from /geras/%subtask_id%/tag_ig
    subtask_tag_name    String, -- from /geras/%subtask_id%/tag_name
    subtask_srpm        String, -- from /geras/%subtask_id%/srpm
    subtask_srpm_name   String, -- from /geras/%subtask_id%/nevr
    subtask_srpm_evr    String, -- from /geras/%subtask_id%/nevr
    ts                  DateTime MATERIALIZED now() -- DEBUG
) ENGINE = ReplacingMergeTree ORDER BY (task_id, subtask_id, task_changed, subtask_changed, subtask_deleted) PRIMARY KEY (task_id, subtask_id);
-- ) ENGINE = ReplacingMergeTree ORDER BY (task_id, subtask_id, subtask_changed, subtask_deleted) PRIMARY KEY (task_id, subtask_id);

CREATE TABLE Tasks_buffer AS Tasks ENGINE = Buffer(currentDatabase(), Tasks, 16, 10, 100, 1000, 100000, 100000, 1000000);


CREATE TABLE TaskStates
(
    task_changed        DateTime, -- from /task/state mtime         
    task_id             UInt32,
    task_state          LowCardinality(String), -- from /task/state
    task_runby          LowCardinality(String), -- from /task/run
    task_depends        Array(UInt32), -- from /task/depends
    task_try            UInt16, -- from /task/try
    task_testonly       UInt8, -- from /task/test-only (is exists)
    task_failearly      UInt8, -- from /task/fail-early (is exists)
    task_shared         UInt8, -- from /info.json
    task_message        String, -- from /task/message
    task_version        String, -- from /task/version
    task_prev           UInt32, -- from /build/repo/prev symlink target
    task_eventlog_hash  Array(UInt64), -- events logs hashes 
    ts              DateTime MATERIALIZED now() -- DEBUG
) ENGINE = ReplacingMergeTree ORDER BY (task_changed, task_id, task_state, task_try) PRIMARY KEY (task_changed, task_id);
--) ENGINE = MergeTree ORDER BY (task_changed, task_id, task_state, task_try) PRIMARY KEY (task_changed, task_id);

CREATE TABLE TaskStates_buffer AS TaskStates ENGINE = Buffer(currentDatabase(), TaskStates, 16, 10, 100, 1000, 100000, 100000, 1000000);


CREATE TABLE TaskApprovals
(
    task_id         UInt32,
    subtask_id      UInt32,
    tapp_type       Enum8('approve' = 0, 'disapprove' = 1),
    tapp_revoked    UInt8, -- compare with last state form DB
    tapp_date       DateTime, -- from /acl/approved/%subtask_id%/%nickname%
    tapp_name       LowCardinality(String), -- from /acl/approved/%subtask_id%/%nickname%
    tapp_message    String, -- from /acl/approved/%subtask_id%/%nickname%
    ts              DateTime MATERIALIZED now() -- DEBUG
) ENGINE = MergeTree ORDER BY (tapp_date, task_id, subtask_id);


CREATE TABLE TaskIterations
(
    task_id             UInt32,
    task_changed        DateTime, -- from /task/state mtime
    subtask_id          UInt32,
    subtask_arch        LowCardinality(String),    
    titer_ts            DateTime, -- from /build/%subtask_id%/%build_arch%/status mtime
    titer_status        LowCardinality(String), -- from /build/%subtask_id%/%build_arch%/status, if empty then 'failed'
    task_try            UInt16, -- from /task/try
    task_iter           UInt8,  -- from /task/iter
    titer_srcrpm_hash   UInt64,
    titer_pkgs_hash     Array(UInt64),
    titer_chroot_base   UInt64, -- change to UInt64 hash if 'TaskChroots' implemented
    titer_chroot_br     UInt64, -- change to UInt64 hash if 'TaskChroots' implemented
    titer_buildlog_hash UInt64, -- build log hash
    titer_srpmlog_hash  UInt64  -- srpm build log hash
) ENGINE = ReplacingMergeTree ORDER BY (task_id, subtask_id, subtask_arch, task_changed, titer_ts, titer_status, task_try, task_iter) PRIMARY KEY (task_id, subtask_id);
-- ) ENGINE = ReplacingMergeTree ORDER BY (task_id, subtask_id, subtask_arch, titer_ts, titer_status, task_try, task_iter) PRIMARY KEY (task_id, subtask_id);

CREATE TABLE TaskIterations_buffer AS TaskIterations ENGINE = Buffer(currentDatabase(), TaskIterations, 16, 10, 100, 1000, 100000, 1000000, 10000000);


CREATE TABLE TaskChroots
(
    tch_hash        UInt64 MATERIALIZED murmurHash3_64(tch_chroot),
    tch_chroot      Array(UInt64)
) ENGINE = ReplacingMergeTree ORDER BY (tch_chroot);

CREATE TABLE TaskChroots_buffer AS TaskChroots ENGINE = Buffer(currentDatabase(), TaskChroots, 16, 10, 100, 1000, 100000, 1000000, 10000000);


CREATE TABLE TaskLogs
(
    tlog_hash           UInt64, -- hash from log file keys string
    tlog_line           UInt32, -- line number
    tlog_ts             DateTime, -- log line timestamp
    tlog_message        String -- log line contents
) ENGINE = ReplacingMergeTree() ORDER BY (tlog_message, tlog_line, tlog_hash);

CREATE TABLE TaskLogs_buffer AS TaskLogs ENGINE = Buffer(currentDatabase(), TaskLogs, 16, 10, 100, 1000, 100000, 1000000, 10000000);


CREATE TABLE TaskPlanPackages
(
    tplan_hash      UInt64,
    tplan_action    Enum8('add' = 0, 'delete' = 1),
    tplan_pkg_name  String,
    tplan_pkg_evr   String,
    tplan_bin_file  String,
    tplan_src_file  String
) ENGINE = ReplacingMergeTree() ORDER BY (tplan_hash, tplan_action, tplan_src_file, tplan_bin_file);


CREATE TABLE TaskPlanPkgHash
(
    tplan_hash      UInt64,
    tplan_action    Enum8('add' = 0, 'delete' = 1),
    tplan_sha256    FixedString(32)
) ENGINE = ReplacingMergeTree() ORDER BY (tplan_hash, tplan_action, tplan_sha256);


CREATE TABLE Files
(
    pkg_hash        UInt64,
    file_hashname   UInt64,
    file_hashdir    UInt64,
    file_linkto     String,
    file_md5        FixedString(16),
    file_size       UInt32,
    file_mode       UInt16,
    file_rdev       UInt16,
    file_mtime      DateTime,
    file_flag       UInt16,
    file_username   LowCardinality(String),
    file_groupname  LowCardinality(String),
    file_verifyflag UInt32,
    file_device     UInt32,
    file_lang       LowCardinality(String),
    file_class      Enum8('file' = 0, 'directory' = 1, 'symlink' = 2, 'socket' = 3, 'block' = 4, 'char' = 5, 'fifo' = 6)
) ENGINE = ReplacingMergeTree ORDER BY (pkg_hash, file_hashname, file_class, file_md5) PRIMARY KEY (pkg_hash, file_hashname);

CREATE TABLE Files_buffer AS Files ENGINE = Buffer(currentDatabase(), Files, 16, 10, 100, 1000, 100000, 1000000, 10000000);


CREATE TABLE FileNames
(
    fn_name       String,
    fn_hash   UInt64 MATERIALIZED murmurHash3_64(fn_name)
)
ENGINE = ReplacingMergeTree ORDER BY fn_name;

CREATE TABLE FileNames_buffer AS FileNames ENGINE = Buffer(currentDatabase(), FileNames, 16, 10, 100, 1000, 100000, 1000000, 10000000);


CREATE 
OR REPLACE VIEW Files_view AS
SELECT
    fn_name as file_name,
    FLS.*
FROM FileNames_buffer 
INNER JOIN (
    SELECT *
    FROM Files_buffer
) AS FLS ON fn_hash = FLS.file_hashname;


CREATE TABLE Files_insert
(
    pkg_hash        UInt64,
    file_name       String,
    file_linkto     String,
    file_md5        FixedString(16),
    file_size       UInt32,
    file_mode       UInt16,
    file_rdev       UInt16,
    file_mtime      DateTime,
    file_flag       UInt16,
    file_username   LowCardinality(String),
    file_groupname  LowCardinality(String),
    file_verifyflag UInt32,
    file_device     UInt32,
    file_lang       LowCardinality(String),
    file_class      Enum8('file' = 0, 'directory' = 1, 'symlink' = 2, 'socket' = 3, 'block' = 4, 'char' = 5, 'fifo' = 6)
) ENGINE = Null;


CREATE MATERIALIZED VIEW mv_files TO Files_buffer
(
    pkg_hash        UInt64,
    file_hashname   UInt64,
    file_hashdir    UInt64,
    file_linkto     String,
    file_md5        FixedString(16),
    file_size       UInt32,
    file_mode       UInt16,
    file_rdev       UInt16,
    file_mtime      DateTime,
    file_flag       UInt16,
    file_username   LowCardinality(String),
    file_groupname  LowCardinality(String),
    file_verifyflag UInt32,
    file_device     UInt32,
    file_lang       LowCardinality(String),
    file_class      Enum8('file' = 0, 'directory' = 1, 'symlink' = 2, 'socket' = 3, 'block' = 4, 'char' = 5, 'fifo' = 6)
) AS SELECT
    pkg_hash, file_linkto, file_md5, file_size, file_mode, file_rdev, file_mtime,
    file_flag, file_username, file_groupname, file_verifyflag, file_device, file_lang, file_class,
    murmurHash3_64(file_name) as file_hashname,
    murmurHash3_64(arrayStringConcat(arrayPopBack(splitByChar('/', file_name)),'/')) as file_hashdir
FROM Files_insert;

CREATE MATERIALIZED VIEW mv_filenames_filename TO FileNames_buffer
(
    fn_name         String
) AS SELECT file_name as fn_name FROM Files_insert;

CREATE MATERIALIZED VIEW mv_filenames_filedir TO FileNames_buffer
(
    fn_name         String
) AS SELECT arrayStringConcat(arrayPopBack(splitByChar('/', file_name)),'/') as fn_name FROM Files_insert;


CREATE TABLE Packages
(
    pkg_hash              UInt64,
    pkg_cs                FixedString(20),
    pkg_packager          LowCardinality(String),
    pkg_packager_email    LowCardinality(String),
    pkg_name              String,
    pkg_arch              LowCardinality(String),
    pkg_version           String,
    pkg_release           String,
    pkg_epoch             UInt32,
    pkg_serial_           UInt32,
    pkg_buildtime         UInt32,
    pkg_buildhost         LowCardinality(String),
    pkg_size              UInt64,
    pkg_archivesize       UInt64,
    pkg_filesize          UInt64, -- actual file size from '.rpm' file stat
    pkg_rpmversion        LowCardinality(String),
    pkg_cookie            String,
    pkg_sourcepackage     UInt8,
    pkg_disttag           String,
    pkg_sourcerpm         String,
    pkg_srcrpm_hash       UInt64,
    pkg_filename          String,
    pkg_complete          UInt8,
    pkg_summary           String,
    pkg_description       String,
    pkg_changelog         Nested(date DateTime, name String, evr String, hash UInt64),
    pkg_distribution      LowCardinality(String),
    pkg_vendor            LowCardinality(String),
    pkg_gif               String,
    pkg_xpm               String,
    pkg_license           LowCardinality(String),
    pkg_group_            String,
    pkg_url               LowCardinality(String),
    pkg_os                LowCardinality(String),
    pkg_prein             String,
    pkg_postin            String,
    pkg_preun             String,
    pkg_postun            String,
    pkg_icon              String,
    pkg_preinprog         Array(String),
    pkg_postinprog        Array(String),
    pkg_preunprog         Array(String),
    pkg_postunprog        Array(String),
    pkg_buildarchs        Array(LowCardinality(String)),
    pkg_verifyscript      String,
    pkg_verifyscriptprog  Array(String),
    pkg_prefixes          Array(LowCardinality(String)),
    pkg_instprefixes      Array(String),
    pkg_optflags          LowCardinality(String),
    pkg_disturl           String,
    pkg_payloadformat     LowCardinality(String),
    pkg_payloadcompressor LowCardinality(String),
    pkg_payloadflags      LowCardinality(String),
    pkg_platform          LowCardinality(String)
) ENGINE = ReplacingMergeTree ORDER BY (pkg_name, pkg_arch, pkg_hash, pkg_srcrpm_hash, pkg_packager,
                                        pkg_packager_email) PRIMARY KEY (pkg_name, pkg_arch) SETTINGS index_granularity = 8192;


CREATE TABLE Packages_buffer AS Packages ENGINE = Buffer(currentDatabase(), Packages, 16, 10, 200, 10000, 1000000,
                                                10000000, 100000000);


CREATE TABLE Changelog
(
    chlog_hash  UInt64,
    chlog_text  String
) ENGINE = ReplacingMergeTree ORDER BY (chlog_hash, chlog_text) PRIMARY KEY chlog_hash;


CREATE TABLE Changelog_buffer AS Changelog ENGINE = Buffer(currentDatabase(), Changelog, 16, 10, 100, 1000, 1000000, 1000000, 10000000);


CREATE 
OR REPLACE VIEW PackageChangelog_view AS
SELECT
    pkg_hash,
    groupArray((toDate(pkg_changelog.date), pkg_changelog.name, pkg_changelog.evr, chlog_text)) AS changelog
FROM 
(
    SELECT DISTINCT *
    FROM 
    (
        SELECT
            pkg_hash,
            pkg_changelog.date,
            pkg_changelog.name,
            pkg_changelog.evr,
            pkg_changelog.hash AS hash,
            Chg.chlog_text
        FROM Packages_buffer
        ARRAY JOIN pkg_changelog
        INNER JOIN 
        (
            SELECT
                chlog_hash AS hash,
                chlog_text
            FROM Changelog_buffer
        ) AS Chg USING (hash)
    )
    ORDER BY pkg_changelog.date DESC
)
GROUP BY pkg_hash;


CREATE 
OR REPLACE VIEW PackagesWithLastChangelog_view AS
SELECT DISTINCT
    PKG.* EXCEPT (pkg_changelog_hash), chlog_text AS pkg_changelog_message
FROM Changelog_buffer
    RIGHT JOIN (
        SELECT * EXCEPT ('pkg_changelog.*'),
            toDate(pkg_changelog.date[1]) AS pkg_changelog_date, pkg_changelog.name[1] AS pkg_changelog_name,
            pkg_changelog.evr[1] AS pkg_changelog_evr, pkg_changelog.hash[1] as pkg_changelog_hash
        FROM Packages_buffer) AS PKG ON chlog_hash = PKG.pkg_changelog_hash;


CREATE TABLE Depends
(
    pkg_hash   UInt64,
    dp_name    String,
    dp_version String,
    dp_flag    UInt32,
    dp_type    Enum8('require' = 1, 'conflict' = 2, 'obsolete' = 3, 'provide' = 4)
) ENGINE = ReplacingMergeTree ORDER BY (dp_name, dp_version, dp_type, dp_flag, pkg_hash) PRIMARY KEY dp_name;

CREATE TABLE Depends_buffer AS Depends ENGINE = Buffer(currentDatabase(), Depends, 16, 10, 200, 10000, 1000000, 1000000, 10000000);


CREATE TABLE Acl
(
    acl_date   DateTime,
    acl_for    String,
    acl_branch String,
    acl_list   Array(String)
) ENGINE = MergeTree ORDER BY (acl_date, acl_branch, acl_for, acl_list) PRIMARY KEY (acl_date, acl_branch);

CREATE TABLE Cve
(
    pkg_hash                        UInt64,
    cve_id                          String,
    cve_description                 String,
    cve_url                         String,
    cve_score                       Float64,
    cve_attacktype                  String,
    cve_status                      Enum8('check' = 0, 'patched' = 1, 'discarded_by_version_check' = 2),
    cve_uris                        Array(String),
    cve_modifieddate                DateTime,
    cve_parsingdate                 DateTime,
    cve_cpe                         String,
    cve_version_start_excluding     Nullable(String),
    cve_version_start_including     Nullable(String),
    cve_version_end_excluding       Nullable(String),
    cve_version_end_including       Nullable(String)
) ENGINE = MergeTree ORDER BY (pkg_hash, cve_id, cve_modifieddate, cve_parsingdate);

CREATE TABLE CveAbsentPackages
(
    cap_product_name    String,
    cve_id              String,
    cve_description     String,
    cve_url             String,
    cve_score           Float64,
    cve_attacktype      String,
    cve_uris            Array(String),
    cve_modifieddate    DateTime,
    cve_parsingdate     DateTime
) ENGINE = MergeTree ORDER BY (cap_product_name, cve_id, cve_modifieddate, cve_parsingdate);

CREATE TABLE CveChecked
(
    cve_id                    String,
    pkg_name                  String,
    cc_checkdate              DateTime,
    cc_description            String,
    cc_description_ru         String,
    `cc_checked_ver.pkg_evr`    Array(String),
    `cc_checked_ver.pkg_branch` Array(String)
)
    ENGINE = MergeTree PRIMARY KEY (cve_id, pkg_name) ORDER BY (cve_id, pkg_name, cc_checkdate) SETTINGS index_granularity = 8192;

CREATE TABLE FstecBduList
(
    bdu_identifier     String,
    bdu_name           String,
    bdu_description    String,
    bdu_identify_date  Date,
    bdu_severity       String,
    bdu_solution       String,
    bdu_vul_status     String,
    bdu_exploit_status String,
    bdu_fix_status     String,
    bdu_sources        String,
    bdu_other          String,
    bdu_vulnerable_software Nested ( vendor String, type Array(String), name String, version String ),
    bdu_environment Nested ( vendor String, version String, name String, platform String ),
    bdu_cwe Nested ( identifier String ),
    bdu_cvss Nested ( vector String, score Float32 ),
    bdu_identifiers Nested ( identifier String, type String, link String )
)
    ENGINE = MergeTree ORDER BY (bdu_identifier, bdu_identify_date, bdu_name) PRIMARY KEY (bdu_identifier, bdu_identify_date);


-- VIEW TABLES --
CREATE
OR REPLACE VIEW task_plan_hashes AS
SELECT task_id, murmurHash3_64(concat(hash_string, archs)) AS tplan_hash
FROM (
    SELECT DISTINCT task_id,
                    concat(toString(task_id), toString(task_try), toString(task_iter)) AS hash_string,
                    arrayConcat(groupUniqArray(subtask_arch), ['src', 'noarch', 'x86_64-i586']) AS archs
    FROM TaskIterations_buffer
    WHERE (task_try, task_iter) IN　(
        SELECT argMax(task_try, task_changed) AS try, argMax(task_iter, task_changed) AS iter
        FROM TaskIterations_buffer
        GROUP BY task_id
    ) AND task_id IN (
        SELECT task_id
        FROM TaskStates
        WHERE task_state = 'DONE'
    )
    GROUP BY task_id, hash_string
) ARRAY JOIN archs;


CREATE
OR REPLACE VIEW last_pkgnames_without_pname AS
SELECT
    *,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'class')] AS pkgset_class
FROM PackageSetName
RIGHT JOIN 
(
    SELECT
        argMax(pkgset_ruuid, pkgset_date) AS pkgset_ruuid,
        pkgset_nodename AS pkgset_name
    FROM PackageSetName
    WHERE pkgset_depth = 0
    GROUP BY pkgset_name
) AS RootPkgs USING (pkgset_ruuid)
ORDER BY
    pkgset_name ASC,
    pkgset_depth ASC;


CREATE
OR REPLACE VIEW last_pkgnames AS
SELECT
    last_pkgnames_without_pname.*,
    PkgSetParent.pkgset_pname AS pkgset_pname
FROM last_pkgnames_without_pname
LEFT JOIN 
(
    SELECT
        pkgset_uuid,
        pkgset_nodename AS pkgset_pname
    FROM PackageSetName
) AS PkgSetParent ON PkgSetParent.pkgset_uuid = pkgset_puuid;


CREATE
OR REPLACE VIEW last_pkgset AS
SELECT *
FROM last_pkgnames
INNER JOIN 
(
    SELECT *
    FROM PackageSet_buffer
    WHERE pkgset_uuid IN 
    (
        SELECT pkgset_uuid
        FROM last_pkgnames
    )
) AS PkgSet USING (pkgset_uuid);


-- CREATE
-- OR REPLACE VIEW last_packages AS
-- SELECT *
-- FROM last_pkgset
-- INNER JOIN 
-- (
--     SELECT * EXCEPT pkg_cs, lower(hex(pkg_cs)) as pkg_cs
--     FROM Packages_buffer
-- ) AS Packages USING (pkg_hash);

-- New last_packages
CREATE
OR REPLACE VIEW last_packages AS
SELECT * EXCEPT pkg_cs, lower(hex(pkg_cs)) as pkg_cs
FROM Packages_buffer
INNER JOIN 
(
    SELECT pkg_hash, pkgset_name, pkgset_date
    FROM static_last_packages
) AS SLP USING (pkg_hash);


CREATE
OR REPLACE VIEW last_depends AS
SELECT Depends_buffer.*,
       pkg_name,
       pkg_version,
       pkgset_name,
       pkgset_date,
       pkg_sourcepackage,
       pkg_arch,
       pkg_filename,
       pkg_sourcerpm
FROM Depends_buffer ALL
         INNER JOIN (SELECT pkg_hash,
                            pkg_name,
                            pkg_version,
                            pkgset_name,
                            pkgset_date,
                            pkg_sourcepackage,
                            pkg_arch,
                            pkg_filename,
                            pkg_sourcerpm
                     FROM last_packages) AS PkgSet USING (pkg_hash);

-- VIEW to JOIN binary and source package

CREATE
OR REPLACE VIEW all_packages_with_source AS
SELECT Packages_buffer.*, srcPackage.*
FROM Packages_buffer
    LEFT JOIN ( SELECT pkg_hash AS pkg_srcrpm_hash, pkg_name AS sourcepkgname
                FROM Packages_buffer
                WHERE pkg_sourcepackage = 1 ) AS srcPackage USING (pkg_srcrpm_hash)
WHERE (pkg_sourcepackage = 0) AND (Packages_buffer.pkg_srcrpm_hash != 0);


CREATE
OR REPLACE VIEW all_pkgnames_without_pname AS
SELECT
    *,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'class')] AS pkgset_class
FROM PackageSetName
RIGHT JOIN 
(
    SELECT
        pkgset_ruuid,
        pkgset_nodename AS pkgset_name
    FROM PackageSetName
    WHERE pkgset_depth = 0
) AS RootPkgs USING (pkgset_ruuid)
ORDER BY
    pkgset_name ASC,
    pkgset_depth ASC;


CREATE 
OR REPLACE VIEW all_pkgnames AS
SELECT
    all_pkgnames_without_pname.*,
    PkgSetParent.pkgset_pname AS pkgset_pname
FROM all_pkgnames_without_pname
LEFT JOIN 
(
    SELECT
        pkgset_uuid,
        pkgset_nodename AS pkgset_pname
    FROM PackageSetName
) AS PkgSetParent ON PkgSetParent.pkgset_uuid = pkgset_puuid;


CREATE
OR REPLACE VIEW all_pkgset AS
SELECT *
FROM all_pkgnames
INNER JOIN 
(
    SELECT *
    FROM PackageSet_buffer
) AS PkgSet USING (pkgset_uuid);


CREATE
OR REPLACE VIEW all_packages AS
SELECT *
FROM all_pkgset
INNER JOIN 
(
    SELECT
        * EXCEPT pkg_cs,
        lower(hex(pkg_cs)) AS pkg_cs
    FROM Packages_buffer
) AS Packages USING (pkg_hash);


-- view to get joined list packages with sourcepackage
CREATE
OR REPLACE VIEW last_packages_with_source AS
SELECT pkg.*, pkgset_name, pkgset_date, pkg_hash
FROM last_pkgset ALL
         INNER JOIN ( SELECT * FROM all_packages_with_source ) AS pkg USING (pkg_hash);

-- view to get last list from ACL
CREATE
OR REPLACE VIEW last_acl AS
SELECT acl_branch, max(acl_date) AS acl_date_last, any(acl_for) AS acl_for, argMax(acl_list, acl_date) AS acl_list
FROM Acl
GROUP BY Acl.acl_branch, Acl.acl_for;

-- view to prepare source packages with array of binary packages
-- CREATE
-- OR REPLACE VIEW source_with_binary_array_packages AS
-- SELECT DISTINCT pkg_hash,
--                 any(pkg_name)                AS pkgname,
--                 any(pkg_version)             AS version,
--                 any(pkg_release)             AS release,
--                 any(pkg_changelog)           AS changelog,
--                 groupUniqArray(name_evr) AS binlist
-- FROM Packages_buffer
--          LEFT JOIN ( SELECT concat(pkg_name, ':', pkg_version, ':', pkg_release) AS name_evr, pkg_sourcerpm AS sourcerpm
--                      FROM Packages_buffer
--                      WHERE (pkg_sourcepackage = 0)
--                        AND (pkg_name NOT LIKE '%-debuginfo')
--                        AND (pkg_name NOT LIKE 'i586-%') ) AS Bin ON Bin.sourcerpm = pkg_filename
-- WHERE pkg_sourcepackage = 1
-- GROUP BY pkg_hash;

-- VIEW to get all pkghash with a unique array of pkgset names

-- CREATE VIEW all_source_pkghash_with_uniq_branch_name (pkg_hash UInt64, pkgset_array Array(String)) AS
-- SELECT pkg_hash, groupUniqArray(pkgset_name) AS pkgset_array
-- FROM all_pkgsets_sources
-- GROUP BY pkg_hash;

-- view to get expanded list ACLs from database with groups
CREATE
OR REPLACE VIEW last_acl_with_groups AS
SELECT acl_branch,
       acl_date_last                                      AS acl_date,
       acl_for                                            AS pkgname,
       if(notEmpty(AclGroups.aclg), AclGroups.aclg, aclu) AS acl_user,
       order_u,
       AclGroups.order_g
FROM last_acl AS AclUsers
         ARRAY JOIN acl_list AS aclu, arrayEnumerate(acl_list) AS order_u
         LEFT JOIN ( SELECT acl_for, aclg, order_g, acl_branch
                     FROM last_acl ARRAY JOIN
                          acl_list AS aclg,
                          arrayEnumerate(acl_list) AS order_g
                     WHERE acl_for LIKE '@%' ) AS AclGroups
                   ON (aclu = AclGroups.acl_for) AND (last_acl.acl_branch = AclGroups.acl_branch)
ORDER BY order_u ASC, order_g ASC;

-- view for all CVE's and packages
CREATE
OR REPLACE VIEW last_cve AS
SELECT *
FROM Cve
         LEFT JOIN last_packages USING (pkg_hash);


-- view for cve-check-tool with source, array of binary packages and changelogs.

-- CREATE
-- OR REPLACE VIEW packages_for_cvecheck AS
-- SELECT pkg_hash, pkg_name, pkg_version, pkg_release, binlist, pkgset_array, changelog
-- FROM Packages
--          LEFT JOIN ( SELECT source_with_binary_array_packages.*, SrcSet.pkgset_array
--                      FROM source_with_binary_array_packages
--                               LEFT JOIN ( SELECT * FROM all_source_pkghash_with_uniq_branch_name ) AS SrcSet
--                                         USING (pkg_hash) ) AS Pkgs USING (pkg_hash)
-- WHERE sourcepackage = 1;


-- Tables and views for static_last_packages build
-- STAGE1 TABLE
-- intermediate table for MV cascading
CREATE TABLE last_packages_stage1
(
    ts DateTime64 MATERIALIZED now64(),
    pkgset_ruuid UUID,
    pkgset_name String,
    pkgset_date DateTime
)
ENGINE = MergeTree()
ORDER BY pkgset_ruuid;

-- FINAL TABLE
-- populated by MV on insert to PackagaSetName table
CREATE TABLE StaticLastPackages
(
    `pkgset_name` String,
    `pkgset_date` DateTime,
    `pkg_hash` UInt64,
    `pkg_name` String,
    `pkg_version` String,
    `pkg_release` String,
    `pkg_sourcepackage` UInt8
)
ENGINE = MergeTree
PRIMARY KEY (pkgset_name, pkg_name)
ORDER BY (pkgset_name, pkg_name, pkg_sourcepackage);

-- Initial StaticLastPackages table fill up
-- INSERT INTO StaticLastPackages SELECT
--     pkgset_name,
--     pkgset_date,
--     pkg_hash,
--     pkg_name,
--     pkg_version,
--     pkg_release,
--     pkg_sourcepackage
-- FROM last_packages
-- WHERE pkgset_name NOT IN 
-- (
--     SELECT DISTINCT pkgset_name
--     FROM StaticLastPackages
-- );

-- Table StaticLastPackages cleun up
-- ALTER TABLE StaticLastPackages DELETE
-- WHERE (pkgset_name, pkgset_date) NOT IN
-- (
--     SELECT
--         argMax(pkgset_name, pkgset_date) AS pkgset_n,
--         max(pkgset_date) AS pkgset_d
--     FROM StaticLastPackages
--     GROUP BY pkgset_name
-- );

-- MV STAGE 1
CREATE MATERIALIZED VIEW mv_last_packages_stage1
TO last_packages_stage1
AS
SELECT
    pkgset_ruuid,
    pkgset_nodename as pkgset_name,
    pkgset_date
FROM PackageSetName
WHERE pkgset_depth = 0;

-- MV STAGE2
CREATE MATERIALIZED VIEW mv_last_packages_stage2
TO StaticLastPackages
AS
SELECT
    pkgset_name,
    pkgset_date,
    LP.*
FROM last_packages_stage1
CROSS JOIN 
(
    SELECT DISTINCT
        pkg_hash,
        pkg_name,
        pkg_version,
        pkg_release,
        pkg_sourcepackage
    FROM Packages_buffer
    WHERE pkg_hash IN 
    (
        SELECT pkg_hash
        FROM PackageSet_buffer
        WHERE pkgset_uuid IN 
        (
            SELECT pkgset_uuid
            FROM PackageSetName
            WHERE pkgset_ruuid IN
            (
                SELECT pkgset_ruuid
                FROM last_packages_stage1
            )
        )
    )
) AS LP;

-- get latest data from StaticLastPackages table for regular selects
CREATE OR REPLACE VIEW static_last_packages AS
SELECT * FROM StaticLastPackages
WHERE (pkgset_name, pkgset_date) IN
(
    SELECT
        argMax(pkgset_name, pkgset_date) AS pkgset_n,
        max(pkgset_date) AS pkgset_d
    FROM StaticLastPackages
    GROUP BY pkgset_name
);
