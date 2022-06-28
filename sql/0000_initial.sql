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
    pkgh_sha256     FixedString(32),
    pkgh_blake2b    FixedString(64)
) ENGINE ReplacingMergeTree ORDER BY (pkgh_mmh, pkgh_md5, pkgh_sha256) PRIMARY KEY pkgh_mmh;

CREATE TABLE PackageHash_buffer AS PackageHash ENGINE = Buffer(currentDatabase(), PackageHash, 16, 10, 100, 10000, 1000000, 1000000, 10000000);

CREATE 
OR REPLACE VIEW PackageHash_view AS
SELECT
    pkgh_mmh,
    lower(hex(pkgh_md5)) as pkgh_md5,
    lower(hex(pkgh_sha1)) as pkgh_sha1,
    lower(hex(pkgh_sha256)) as pkgh_sha256,
    lower(hex(pkgh_blake2b)) as pkgh_blake2b
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
    titer_chroot_base   UInt64, -- tch_hash from TaskChroots
    titer_chroot_br     UInt64, -- tch_hash from TaskChroots
    titer_buildlog_hash UInt64, -- build log hash
    titer_srpmlog_hash  UInt64  -- srpm build log hash
) ENGINE = ReplacingMergeTree ORDER BY (task_id, subtask_id, subtask_arch, task_changed, titer_ts, titer_status, task_try, task_iter) PRIMARY KEY (task_id, subtask_id);

CREATE TABLE TaskIterations_buffer AS TaskIterations ENGINE = Buffer(currentDatabase(), TaskIterations, 16, 10, 100, 1000, 100000, 1000000, 10000000);


CREATE TABLE TaskChroots
(
    tch_hash        UInt64 MATERIALIZED murmurHash3_64(tch_chroot),
    tch_chroot      Array(UInt64)  -- array of mmh3(SHA1)
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
    tplan_src_file  String,
    tplan_arch      LowCardinality(String),
    tplan_comp      LowCardinality(String),
    tplan_subtask   UInt32
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
        FROM Packages
        ARRAY JOIN pkg_changelog
        INNER JOIN 
        (
            SELECT
                chlog_hash AS hash,
                chlog_text
            FROM Changelog_buffer
        ) AS Chg ON Chg.hash = hash
    )
    ORDER BY pkg_changelog.date DESC, pkg_changelog.evr DESC
)
GROUP BY pkg_hash;


-- Materialized view for source packages last changelog
CREATE TABLE SrcPackagesLastChangelog
(
    pkg_hash    UInt64,
    chlog_nick  String,
    chlog_name  String,
    chlog_date  DateTime,
    chlog_evr   String,
    chlog_text  String
) ENGINE = ReplacingMergeTree ORDER BY pkg_hash;

-- populate table with SELECT from MV below
CREATE MATERIALIZED VIEW mv_src_packages_last_changelog TO SrcPackagesLastChangelog AS
SELECT DISTINCT
    pkg_hash,
    extract(replaceOne(extract(pkg_changelog.name[1], '<(.+@?.+)>+'), ' at ', '@'), '(.*)@') AS chlog_nick,
    pkg_changelog.name[1] AS chlog_name,
    pkg_changelog.date[1] AS chlog_date,
    pkg_changelog.evr[1] AS chlog_evr,
    CHG.chlog_text
FROM Packages
LEFT JOIN
(
    SELECT
        chlog_hash,
        chlog_text
    FROM Changelog
) AS CHG ON CHG.chlog_hash = (pkg_changelog.hash[1])
WHERE pkg_sourcepackage = 1;


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
    cve_status                      Enum8('check' = 0, 'patched' = 1, 'discarded_by_version_check' = 2, 'manually_excluded' = 3),
    cve_uris                        Array(String),
    cve_modifieddate                DateTime,
    cve_parsingdate                 DateTime,
    cve_cpe                         String,
    cve_version_start_excluding     Nullable(String),
    cve_version_start_including     Nullable(String),
    cve_version_end_excluding       Nullable(String),
    cve_version_end_including       Nullable(String),
    cc_id                           Nullable(UInt64)
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
    cve_id                      String,
    pkg_name                    String,
    cc_id                       UInt64 MATERIALIZED murmurHash3_64(cve_id, pkg_name, cc_checked_ver.pkg_evr, cc_checked_ver.pkg_branch), -- hash
    cc_status                   Enum8('patched' = 0, 'manually_excluded' = 1),
    cc_checkdate                DateTime,
    cc_description              String,
    cc_description_ru           String,
    `cc_checked_ver.pkg_evr`    Array(String),
    `cc_checked_ver.pkg_branch` Array(String)
)
    ENGINE = MergeTree PRIMARY KEY (cve_id, pkg_name) ORDER BY (cve_id, pkg_name, cc_checkdate);


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


-- Repocop info
CREATE TABLE PackagesRepocop
(
    pkg_name String,
    pkg_version String,
    pkg_release String,
    pkg_arch LowCardinality(String),
    pkgset_name LowCardinality(String),
    rc_srcpkg_name String,
    rc_srcpkg_version String,
    rc_srcpkg_release String,
    rc_test_name LowCardinality(String),
    rc_test_date DateTime,
    rc_test_status LowCardinality(String),
    rc_test_message String,
    ts DateTime64 MATERIALIZED now64()
)
ENGINE = ReplacingMergeTree
ORDER BY (pkg_name, pkg_version, pkg_release, pkg_arch, pkgset_name, rc_test_name, rc_test_date);


-- Bugzilla info
CREATE TABLE Bugzilla
(
    bz_id UInt32,
    bz_status LowCardinality(String),
    bz_resolution LowCardinality(String),
    bz_severity LowCardinality(String),
    bz_product LowCardinality(String),
    bz_component String,
    bz_assignee String,
    bz_reporter String,
    bz_summary String,
    bz_last_changed DateTime,
    bz_assignee_full String,
    bz_reporter_full String,
    ts DateTime64 MATERIALIZED now64()
)
ENGINE = MergeTree
ORDER BY (bz_id, bz_component, bz_assignee) PRIMARY KEY (bz_id);


-- Repository status table
CREATE TABLE RepositoryStatus
(
    pkgset_name             LowCardinality(String),
    rs_start_date           DateTime,
    rs_end_date             DateTime,
    rs_show                 UInt8, -- 0 - hide branch, 1 - show branch
    rs_description_ru       String,
    rs_description_en       String,
    rs_mirrors_json         String, -- package set mirror details as stringified JSON structure
    rs_mailing_list         LowCardinality(String), -- branch mailing list URL
    rs_pkgset_name_bugzilla LowCardinality(String), -- branch name in Bugzilla
    ts DateTime64 MATERIALIZED now64()
)
ENGINE = MergeTree
ORDER BY (pkgset_name, rs_show) PRIMARY KEY (pkgset_name);


-- Beehive build status table
CREATE TABLE BeehiveStatus
(
    pkg_hash        UInt64,
    pkg_name        String,
    pkg_version     String,
    pkg_release     String,
    pkgset_name     LowCardinality(String),
    bh_arch         LowCardinality(String),
    bh_status       Enum('error' = 0, 'success' = 1),
    bh_build_time   Float32,
    bh_updated      DateTime,
    bh_ftbfs_since  DateTime
)
ENGINE = MergeTree
ORDER BY (pkgset_name, pkg_name, bh_updated, bh_arch, pkg_hash)
PRIMARY KEY (pkgset_name, pkg_name);


-- Source packages spec files tables
CREATE TABLE Specfiles_insert
(
    pkg_hash UInt64,
    pkg_name String,
    pkg_epoch UInt32,
    pkg_version String,
    pkg_release String,
    specfile_name String,
    specfile_date DateTime,
    specfile_content_base64 String
)
ENGINE = Null;


CREATE TABLE Specfiles
(
    pkg_hash UInt64,
    pkg_name String,
    pkg_epoch UInt32,
    pkg_version String,
    pkg_release String,
    specfile_name String,
    specfile_date DateTime,
    specfile_content String
)
ENGINE = ReplacingMergeTree
ORDER BY (pkg_hash, specfile_content);


CREATE TABLE Specfiles_buffer AS Specfiles ENGINE = Buffer(currentDatabase(), Specfiles, 16, 10, 100, 1000, 100000, 100000, 1000000);


CREATE MATERIALIZED VIEW mv_specfiles TO Specfiles_buffer
(
    pkg_hash UInt64,
    pkg_name String,
    pkg_epoch UInt32,
    pkg_version String,
    pkg_release String,
    specfile_name String,
    specfile_date DateTime,
    specfile_content String
)
AS SELECT
    pkg_hash, pkg_name, pkg_epoch, pkg_version, pkg_release,
    specfile_name, specfile_date, base64Decode(specfile_content_base64) as specfile_content
FROM Specfiles_insert;

-- VIEW TABLES --
CREATE
OR REPLACE VIEW task_plan_hashes AS
SELECT DISTINCT
    task_id,
    murmurHash3_64(concat(toString(task_id), toString(task_try), toString(task_iter), archs)) AS tplan_hash,
    archs AS tplan_arch
FROM
(
    SELECT
        task_id,
        argMax(task_try, task_changed) AS task_try,
        argMax(task_iter, task_changed) AS task_iter,
        arrayConcat(groupUniqArray(subtask_arch), ['src', 'noarch', 'x86_64-i586']) AS archs
    FROM TaskIterations
    WHERE task_id IN (
        SELECT task_id
        FROM TaskStates
        WHERE task_state = 'DONE'
    )
    GROUP BY task_id
)
ARRAY JOIN archs;


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
) AS RootPkgs USING (pkgset_ruuid);


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

-- Table StaticLastPackages clean up
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
WHERE pkgset_depth = 0
    AND pkgset_kv.v[indexOf(pkgset_kv.k, 'class')] = 'repository';

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


CREATE
OR REPLACE VIEW last_packages AS
SELECT * EXCEPT pkg_cs, lower(hex(pkg_cs)) as pkg_cs
FROM Packages_buffer
INNER JOIN
(
    SELECT pkg_hash, pkgset_name, pkgset_date
    FROM static_last_packages
) AS SLP USING (pkg_hash);


-- add live view table for fast package set statistics
SET allow_experimental_live_view=1;

CREATE LIVE VIEW lv_pkgset_stat AS
SELECT
    pkgset_name,
    pkgset_date,
    if(P.pkg_sourcepackage = 1, 'srpm', P.pkg_arch) AS pkg_arch,
    countDistinct(src_pkg_name) AS cnt
FROM StaticLastPackages
LEFT JOIN
(
    SELECT
        pkg_hash,
        pkg_sourcepackage,
        pkg_arch,
        pkg_sourcerpm AS src_pkg_name
    FROM Packages_buffer
) AS P ON P.pkg_hash = StaticLastPackages.pkg_hash
WHERE (P.pkg_arch != 'x86_64-i586') AND ((pkgset_name, pkgset_date) IN (
    SELECT
        argMax(pkgset_name, pkgset_date) AS pkgset_n,
        max(pkgset_date) AS pkgset_d
    FROM StaticLastPackages
    GROUP BY pkgset_name
))
GROUP BY
    pkgset_name,
    pkgset_date,
    pkg_arch;


CREATE
OR REPLACE VIEW last_depends AS
SELECT 
    Depends.*,
    pkg_name,
    pkg_version,
    pkgset_name,
    pkgset_date,
    pkg_sourcepackage,
    pkg_arch,
    pkg_filename,
    pkg_sourcerpm
FROM Depends ALL
INNER JOIN 
(
    SELECT
        pkg_hash,
        pkg_name,
        pkg_version,
        pkgset_name,
        pkgset_date,
        pkg_sourcepackage,
        pkg_arch,
        pkg_filename,
        pkg_sourcerpm
    FROM last_packages
) AS PkgSet USING (pkg_hash);


-- table with [source package name : binary package name] pairs
-- populate for migration with SELECT from mv_packages_source_and_binaries below
CREATE TABLE PackagesSourceAndBinaries
(
    buildtime       SimpleAggregateFunction(max, UInt32),
    src_pkg_name    String,
    bin_pkg_name    String
)
ENGINE = AggregatingMergeTree
ORDER BY (src_pkg_name, bin_pkg_name);

-- MV for PackagesSourceAndBinaries
CREATE MATERIALIZED VIEW mv_packages_source_and_binaries TO PackagesSourceAndBinaries AS
SELECT DISTINCT
    max(pkg_buildtime) AS buildtime,
    arrayStringConcat(arrayPopBack(arrayPopBack(splitByChar('-', pkg_sourcerpm))), '-') AS src_pkg_name,
    pkg_name AS bin_pkg_name
FROM Packages
WHERE pkg_srcrpm_hash != 0
    AND pkg_name NOT LIKE 'i586-%'
GROUP BY
    src_pkg_name,
    pkg_name;


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


-- view for all CVE's and packages
CREATE
OR REPLACE VIEW last_cve AS
SELECT *
FROM Cve
         LEFT JOIN last_packages USING (pkg_hash);


-- intermediate table for MV cascading
CREATE TABLE last_acl_stage1
(
    acl_branch      String,
    acl_date_last   SimpleAggregateFunction(max, DateTime),
    acl_for         String,
    acl_list        SimpleAggregateFunction(anyLast, Array(String))
)
ENGINE = AggregatingMergeTree
ORDER BY (acl_branch, acl_for);


-- materialized view  for last ACL
CREATE MATERIALIZED VIEW mv_last_acl TO last_acl_stage1 AS
SELECT
    acl_branch,
    max(acl_date) as acl_date_last,
    acl_for,
    argMax(acl_list, acl_date) as acl_list
FROM Acl
GROUP BY
    acl_branch,
    acl_for;


-- view to get expanded list ACLs from database with groups
CREATE OR REPLACE VIEW last_acl_with_groups
(
    acl_branch  String,
    acl_date    DateTime,
    pkgname     String,
    acl_user    String,
    order_u     UInt32,
    order_g     UInt32
) AS
SELECT
    acl_branch,
    max(acl_date_last) AS acl_date,
    acl_for AS pkgname,
    argMax(if(notEmpty(AclGroups.aclg), AclGroups.aclg, aclu), acl_date_last) AS acl_user,
    order_u,
    AclGroups.order_g
FROM last_acl_stage1
ARRAY JOIN
    acl_list AS aclu,
    arrayEnumerate(acl_list) AS order_u
LEFT JOIN
(
    SELECT
        acl_for,
        aclg,
        order_g,
        acl_branch
    FROM last_acl_stage1
ARRAY JOIN
        acl_list AS aclg,
        arrayEnumerate(acl_list) AS order_g
    WHERE acl_for LIKE '@%'
) AS AclGroups ON (aclu = AclGroups.acl_for) AND (last_acl_stage1.acl_branch = AclGroups.acl_branch)
GROUP BY
    acl_for,
    acl_branch,
    order_u,
    AclGroups.order_g
ORDER BY
    order_u ASC,
    order_g ASC;

-- add table for Watch partitioned by month
CREATE TABLE PackagesWatch
(
    acl             String,
    pkg_name        String,
    old_version     String,
    new_version     String,
    url             String,
    date_update     DateTime
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(date_update)
ORDER BY (acl, date_update, pkg_name, old_version, new_version, url);


-- Distribution images related tables
-- table for unpacked images package set roots
CREATE TABLE ImagePackageSetName
(
    pkgset_uuid         UUID,
    pkgset_date         DateTime,
    img_tag             String,
    img_branch          LowCardinality(String),
    img_edition         LowCardinality(String),
    img_flavor          LowCardinality(String),
    img_platform        LowCardinality(String),
    img_release         LowCardinality(String),
    img_version_major   UInt32,
    img_version_minor   UInt32,
    img_version_sub     UInt32,
    img_arch            LowCardinality(String),
    img_variant         LowCardinality(String),
    img_type            LowCardinality(String),
    img_kv              Map(String,String),
    ts                  DateTime64(3) MATERIALIZED now64()
) ENGINE = MergeTree
PRIMARY KEY (pkgset_date, img_branch, img_edition)
ORDER BY (pkgset_date, img_branch, img_edition, img_arch, img_variant, img_release);

-- MV for image package set
CREATE MATERIALIZED VIEW mv_image_pkgset TO ImagePackageSetName
(
    pkgset_uuid         UUID,
    pkgset_date         DateTime,
    img_tag             String,
    img_branch          LowCardinality(String),
    img_edition         LowCardinality(String),
    img_flavor          LowCardinality(String),
    img_platform        LowCardinality(String),
    img_release         LowCardinality(String),
    img_version_major   UInt32,
    img_version_minor   UInt32,
    img_version_sub     UInt32,
    img_arch            LowCardinality(String),
    img_variant         LowCardinality(String),
    img_type            LowCardinality(String),
    img_kv              Map(String,String)
) AS SELECT
    pkgset_uuid,
    pkgset_date,
    pkgset_tag AS img_tag,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'branch')] AS img_branch,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'edition')] AS img_edition,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'flavor')] AS img_flavor,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'platform')] AS img_platform,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'release')] AS img_release,
    toUInt32(pkgset_kv.v[indexOf(pkgset_kv.k, 'version_major')]) AS img_version_major,
    toUInt32(pkgset_kv.v[indexOf(pkgset_kv.k, 'version_minor')]) AS img_version_minor,
    toUInt32(pkgset_kv.v[indexOf(pkgset_kv.k, 'version_sub')]) AS img_version_sub,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'arch')] AS img_arch,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'variant')] AS img_variant,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'image_type')] AS img_type,
    MAP.kv as img_kv
FROM PackageSetName
LEFT JOIN
(
    SELECT
        pkgset_uuid,
        cast(arrayZip(groupArray(arrayJoin(pkgset_kv.k) AS K), groupArray(pkgset_kv.v[indexOf(pkgset_kv.k, K)] AS V)), 'Map(String,String)') AS kv
    FROM PackageSetName
    WHERE pkgset_depth = 0
        AND pkgset_kv.v[indexOf(pkgset_kv.k, 'class')] != 'repository'
        AND K NOT IN ['branch', 'edition', 'flavor', 'platform', 'release', 'version_major', 'version_minor', 'version_sub', 'arch', 'variant', 'image_type']
    GROUP BY pkgset_uuid
) AS MAP USING pkgset_uuid
WHERE pkgset_depth = 0 AND pkgset_kv.v[indexOf(pkgset_kv.k, 'class')] != 'repository';


-- Image status table
CREATE TABLE ImageStatus
(
    img_branch              LowCardinality(String),
    img_edition             LowCardinality(String),
    img_name                String, -- official image name
    img_show                Enum8('hide' = 0, 'show' = 1),
    img_start_date          DateTime,
    img_end_date            DateTime,
    img_summary_ru          String, -- short description RU
    img_summary_en          String, -- short description EN
    img_description_ru      String,
    img_description_en      String,
    img_mailing_list        LowCardinality(String), -- image edition mailing list URL
    img_name_bugzilla       LowCardinality(String), -- image name in Bugzilla
    img_json                String, -- image auxilary data as stringified JSON structure
    ts                      DateTime64 MATERIALIZED  now64()
)
ENGINE = MergeTree
ORDER BY (img_branch, img_edition, img_show) PRIMARY KEY (img_branch, img_edition);

-- Image status by tag table
CREATE TABLE ImageTagStatus
(
    img_tag     String,
    img_show    Enum8('hide' = 0, 'show' = 1),
    ts          DateTime64 MATERIALIZED  now64()
)
ENGINE = ReplacingMergeTree
ORDER BY img_tag;


-- branch packages history from tasks
CREATE TABLE BranchPackageHistory
(
    pkgset_name         LowCardinality(String),
    task_id             UInt32,
    task_changed        DateTime,
    task_message        String,
    tplan_action        Enum8('add' = 0, 'delete' = 1),
    pkg_hash            UInt64,
    pkg_name            String,
    pkg_epoch           UInt32,
    pkg_version         String,
    pkg_release         String,
    pkg_arch            LowCardinality(String),
    pkg_sourcepackage   UInt8,
    chlog_date          DateTime,
    chlog_name          String,
    chlog_nick          LowCardinality(String),
    chlog_evr           String,
    chlog_text          String
)
ENGINE = ReplacingMergeTree
ORDER BY (pkg_hash, pkgset_name, pkg_name, pkg_sourcepackage, task_id);

-- use 'INSERT INTO BranchPackageHistory' instead of MV header to fill in table
CREATE MATERIALIZED VIEW mv_package_history TO BranchPackageHistory
(
    pkgset_name         LowCardinality(String),
    task_id             UInt32,
    task_changed        DateTime,
    task_message        String,
    tplan_action        Enum8('add' = 0, 'delete' = 1),
    pkg_hash            UInt64,
    pkg_name            String,
    pkg_epoch           UInt32,
    pkg_version         String,
    pkg_release         String,
    pkg_arch            LowCardinality(String),
    pkg_sourcepackage   UInt8,
    chlog_date          DateTime,
    chlog_name          String,
    chlog_nick          LowCardinality(String),
    chlog_evr           String,
    chlog_text          String
) AS
SELECT DISTINCT
    pkgset_name,
    task_id,
    task_changed,
    task_message,
    tplan_action,
    pkg_hash,
    pkg_name,
    pkg_epoch,
    pkg_version,
    pkg_release,
    pkg_arch,
    pkg_sourcepackage,
    chlog_date,
    chlog_name,
    extract(replaceOne(extract(chlog_name, '<(.+@?.+)>+'), ' at ', '@'), '(.*)@') AS chlog_nick,
    chlog_evr,
    chlog_text
FROM (
    SELECT *
    FROM (
        SELECT
            TI.*, TPP.tplan_action, TPP.pkg_hash
        FROM (
            SELECT
                task_id,
                task_changed,
                task_message,
                TR.task_repo AS pkgset_name
            FROM TaskStates
            LEFT JOIN (
                SELECT DISTINCT task_id, task_repo
                FROM Tasks
            ) AS TR ON TR.task_id = TaskStates.task_id
            WHERE task_state = 'DONE'
        ) AS TI
        LEFT JOIN (
            SELECT task_id, tplan_hash, PH.tplan_action, PH.pkg_hash
            FROM task_plan_hashes
            LEFT JOIN (
                SELECT
                    tplan_hash,
                    tplan_action,
                    PH.pkgh_mmh AS pkg_hash
                FROM TaskPlanPkgHash
                LEFT JOIN (
                    SELECT
                        pkgh_mmh,
                        pkgh_sha256
                    FROM PackageHash
                ) AS PH ON PH.pkgh_sha256 = tplan_sha256
            ) AS PH ON PH.tplan_hash = task_plan_hashes.tplan_hash
            WHERE pkg_hash != 0
        ) AS TPP ON TPP.task_id = TI.task_id
    ) AS TPI
    LEFT JOIN (
        SELECT
            pkg_hash,
            pkg_name,
            pkg_epoch,
            pkg_version,
            pkg_release,
            pkg_arch,
            pkg_sourcepackage
        FROM Packages
    ) AS PI USING pkg_hash
) AS TPPI
LEFT JOIN (
    SELECT PKGCHLG.* EXCEPT (chlog_hash), CHLG.chlog_text
    FROM (
        SELECT
            pkg_hash,
            pkg_changelog.date[1] AS chlog_date,
            pkg_changelog.name[1] as chlog_name,
            pkg_changelog.evr[1] AS chlog_evr,
            pkg_changelog.hash[1] AS chlog_hash
        FROM Packages
    ) AS PKGCHLG
    LEFT JOIN (
        SELECT chlog_hash, chlog_text
        FROM Changelog
    ) AS CHLG ON CHLG.chlog_hash = PKGCHLG.chlog_hash
) AS PCHLG USING pkg_hash;

-- SPDX licenses table
CREATE TABLE SPDXLicenses
(
    spdx_id         String,
    spdx_name       String,
    spdx_text       String,
    spdx_header     String,
    spdx_urls       Array(String),
    spdx_type       Enum8('license' = 0, 'exception' = 1)
)
ENGINE = ReplacingMergeTree
ORDER BY (spdx_id, spdx_type, spdx_name, spdx_text);

-- License aliases look-up table
CREATE TABLE LicenseAliases
(
    alias       String,
    spdx_id     String
)
ENGINE = ReplacingMergeTree
ORDER BY (alias, spdx_id);


-- task progress table for AMQP messages
CREATE TABLE TaskProgress
(
    task_id             UInt32, -- required
    task_try            UInt16, -- default 0
    task_iter           UInt8,  -- default 0
    subtask_id          UInt32, -- default 0
    tp_girar_user       LowCardinality(String), -- required
    tp_repo             LowCardinality(String), -- required
    tp_owner            LowCardinality(String), -- required
    tp_state            LowCardinality(String), -- required
    tp_task_changed     DateTime,               -- required
    tp_subtask_changed  Nullable(DateTime),     -- DateTime or None
    tp_arch             LowCardinality(String), -- default ''
    tp_json             String, -- message contents as json.dumps(%message%) -- required
    tp_type             Enum8('task' = 0, 'subtask' = 1), -- required
    tp_action           Enum8('state' = 0, 'abort' = 1, 'create' = 2, 'delete' = 3, 'share' = 4, 'deps' = 5, 'approve' = 6, 'disapprove' = 7, 'progress' = 8), -- required
    ts                  DateTime64 MATERIALIZED now64()
)
ENGINE = MergeTree
PRIMARY KEY (task_id)
ORDER BY (task_id, subtask_id, tp_task_changed, tp_type, tp_action);

