CREATE TABLE PackageSetName
(
    pkgset_uuid     UUID,
    pkgset_puuid    UUID,
    pkgset_name     String,
    pkgset_date     DateTime,
    pkgset_tag      String,
    pkgset_complete UInt8,
    pkgset_kv       Nested(k String, v String)
) ENGINE = MergeTree ORDER BY (pkgset_date, pkgset_name) PRIMARY KEY pkgset_date;

CREATE TABLE PackageSet
(
    pkgset_uuid     UUID CODEC(ZSTD(1)),
    pkg_hash        UInt64 CODEC(Gorilla,ZSTD(1))
) ENGINE = MergeTree ORDER BY (pkgset_uuid, pkg_hash) PRIMARY KEY (pkgset_uuid);

CREATE TABLE PackageHashes
(
    pkgh_mmh        UInt64,
    pkgh_md5        FixedString(16),
    pkgh_sha1       FixedString(20),
    pkgh_sha256     FixedString(32)
) ENGINE ReplacingMergeTree ORDER BY (pkgh_mmh, pkgh_md5, pkgh_sha256) PRIMARY KEY pkgh_mmh

CREATE TABLE Tasks
(
    task_id         UInt32,
    task_message    String,
    task_changed    DateTime,
    task_prev       UInt32,
    task_try        UInt16,
    task_iteration  UInt8,
    task_state      LowCardinality(String),
    task_testonly   UInt8,
    task_repo       LowCardinality(String),
    task_owner      LowCardinality(String),
    task_shared     UInt8
) ENGINE = MergeTree ORDER BY (task_id, task_try, task_repo, task_state);

CREATE TABLE TasksSubtasks
(
    task_id              UInt32,
    subtask_id           UInt32,
    subtask_removed      UInt8,
    subtask_changed      DateTime,
    subtask_type         LowCardinality(String),
    subtask_owner        LowCardinality(String),
    subtask_srpm         String,
    subtask_tag_name     String,
    subtask_tag_id       String,
    subtask_tag_author   LowCardinality(String),
    subtask_pkgname      String,
    subtask_copy_package String,
    subtask_copy_repo    LowCardinality(String)
) ENGINE = MergeTree ORDER BY (task_id, subtask_id, subtask_changed);

CREATE TABLE TasksAcl
(
    task_id         UInt32,
    subtask_id      UInt32,
    taskacl_removed UInt8,
    taskacl_changed DateTime,
    taskacl_type    Enum8('approved' = 1, 'disapproved' = 2),
    taskacl_by      String,
    taskacl_message String
) ENGINE = MergeTree ORDER BY (task_id, subtask_id, taskacl_changed);

CREATE TABLE TasksPlan
(
    task_id          UInt32,
    taskplan_uuid    UUID,
    taskplan_changed DateTime,
    taskplan_action  Enum8('remove' = 1, 'add' = 2),
    taskplan_name    String,
    taskplan_EVR     String,


) ENGINE = MergeTree ORDER BY (task_id);

CREATE TABLE Files
(
    pkg_hash        UInt64,
    file_name       String,
    file_hashname   UInt64 MATERIALIZED murmurHash3_64(file_name),
    file_hashdir    UInt64 MATERIALIZED murmurHash3_64(arrayStringConcat(arrayPopBack(splitByChar('/', file_name)))),
    file_linkto     String,
    file_md5        FixedString(32),
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
    file_class      String
) ENGINE = ReplacingMergeTree ORDER BY (pkg_hash, filename, file_class, file_md5) PRIMARY KEY pkg_hash;

CREATE TABLE Packages
(
    pkg_hash              UInt64,
    pkg_cs                FixedString(40),
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
    pkg_rpmversion        LowCardinality(String),
    pkg_cookie            String,
    pkg_sourcepackage     UInt8,
    pkg_disttag           String,
    pkg_sourcerpm         String,
    pkg_filename          String,
    pkg_sha1srcheader     FixedString(40),
    pkg_complete          UInt8,
    pkg_summary           String,
    pkg_description       String,
    pkg_changelog         String,
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
) ENGINE = ReplacingMergeTree ORDER BY (pkg_name, pkg_arch, pkg_version, pkg_release, pkg_serial_, pkg_epoch, pkg_disttag,
                                        pkg_filename, pkg_sourcerpm, pkg_packager,
                                        pkg_packager_email) PRIMARY KEY (pkg_name, pkg_arch) SETTINGS index_granularity = 8192;


CREATE TABLE Depends
(
    pkg_hash   UInt64,
    dp_name    String,
    dp_version String,
    dp_flag    UInt32,
    dp_type    Enum8('require' = 1, 'conflict' = 2, 'obsolete' = 3, 'provide' = 4)
) ENGINE = MergeTree ORDER BY (pkg_hash, dp_type, dp_name, dp_version, dp_flag) PRIMARY KEY pkg_hash;


CREATE TABLE Config
(
    key   String,
    value String
) ENGINE = MergeTree ORDER BY (key, value);

CREATE TABLE Acl
(
    acl_date   DateTime,
    acl_for    String,
    acl_branch String,
    acl_list   Array(String)
) ENGINE = MergeTree ORDER BY (acl_date, acl_branch, acl_for, acl_list) PRIMARY KEY (acl_date, acl_branch);

CREATE TABLE Cve
(
    pkg_hash            UInt64,
    cve_id              String,
    cve_description     String,
    cve_url             String,
    cve_score           Float64,
    cve_attacktype      String,
    cve_status          Enum8('check' = 0, 'patched' = 1),
    cve_uris            Array(String),
    cve_modifieddate    DateTime,
    cve_parsingdate     DateTime
) ENGINE = MergeTree ORDER BY (pkg_hash, cve_id, cve_modifieddate, cve_parsingdate) SETTINGS index_granularity = 8192;

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
) ENGINE = MergeTree ORDER BY (cap_product_name, cve_id, cve_modifieddate, cve_parsingdate) SETTINGS index_granularity = 8192;

CREATE TABLE CveChecked
(
    cve_id                    String,
    pkg_name                  String,
    cc_checkdate              DateTime,
    cc_description            String,
    cc_description_ru         String,
    cc_checked_ver.pkg_evr    Array(String),
    cc_checked_ver.pkg_branch Array(String)
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

CREATE TABLE AptPkgRelease
(
    apr_uuid         UUID,
    apr_tag          String,
    apr_hashrelease  UInt64,
    apr_origin       String,
    apr_label        String,
    apr_suite        String,
    apr_codename     UInt64,
    apr_arch         String,
    apr_archive      String,
    apr_date         DateTime,
    apr_description  String,
    apr_notautomatic UInt8,
    apr_version      UInt64,
    apr_component    String
)
    ENGINE = MergeTree ORDER BY (apr_date, apr_tag, apr_suite, apr_arch, apr_version) PRIMARY KEY (apr_date, apr_tag, apr_suite, apr_arch);

CREATE TABLE AptPkgSet
(
    apr_uuid      UUID,
    aps_uuid      UUID,
    aps_name      String,
    aps_version   String,
    aps_release   String,
    aps_epoch     UInt32,
    aps_serial    UInt32,
    aps_buildtime UInt32,
    aps_disttag   String,
    aps_arch      String,
    aps_sourcerpm String,
    aps_md5       String,
    aps_filesize  UInt64,
    aps_filename  String
) ENGINE = MergeTree ORDER BY (apr_uuid, aps_md5, aps_sourcerpm, aps_filename) PRIMARY KEY (apr_uuid, aps_md5);


CREATE TABLE PackageSet_buffer AS PackageSet ENGINE = Buffer(currentDatabase(), PackageSet, 16, 10, 200, 10000, 1000000,
                                                    10000000, 1000000000);


CREATE TABLE Files_buffer AS Files ENGINE = Buffer(currentDatabase(), Files, 16, 10, 200, 10000, 1000000, 10000000,
                                          1000000000);


CREATE TABLE Packages_buffer AS Packages ENGINE = Buffer(currentDatabase(), Packages, 16, 10, 200, 10000, 1000000,
                                                10000000, 1000000000);


CREATE TABLE Depends_buffer AS Depends ENGINE = Buffer(currentDatabase(), Depends, 16, 10, 200, 10000, 1000000,
                                                10000000, 1000000000);

-- return pkghash, name and date for recent pkgset's

CREATE
OR REPLACE VIEW last_pkgsets AS
SELECT pkg_hash, pkgset_name, date AS pkgset_date
FROM PackageSet_buffer
         RIGHT JOIN ( SELECT argMax(pkgset_uuid, pkgset_date) AS uuid, pkgset_name, max(pkgset_date) AS date
                      FROM PackageSetName
                      GROUP BY pkgset_name ) AS PkgSet USING (pkgset_uuid)
WHERE pkgset_uuid IN (SELECT pkgset_uuid
               FROM (SELECT argMax(pkgset_uuid, pkgset_date) AS uuid, pkgset_name, max(pkgset_date) AS date
                     FROM PackageSetName
                     GROUP BY pkgset_name
                        ));

CREATE
OR REPLACE VIEW last_packages AS
SELECT pkg.*, pkgset_name, pkgset_date, pkg_hash
FROM last_pkgsets ALL
         INNER JOIN (SELECT * FROM Packages_buffer) AS pkg USING (pkg_hash);

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
         LEFT JOIN ( SELECT pkg_hash AS sourcepkghash, pkg_name AS sourcepkgname, pkg_filename AS sourcerpm
                     FROM Packages_buffer
                     WHERE sourcepackage = 1 ) AS srcPackage USING (sourcerpm)
WHERE sourcepackage = 0;

-- view to JOIN all pkgset's for source packages
CREATE
OR REPLACE VIEW all_pkgsets_sources AS
SELECT pkg_hash, pkgset_name, date AS pkgset_date
FROM PackageSet_buffer
         RIGHT JOIN ( SELECT pkgset_uuid, pkgset_name, pkgset_date AS date FROM PackageSetName ) AS PkgSet
                    USING (pkgset_uuid) PREWHERE pkg_hash IN (SELECT pkg_hash FROM Packages WHERE pkg_sourcepackage = 1);

-- view to get joined list packages with sourcepackage
CREATE
OR REPLACE VIEW last_packages_with_source AS
SELECT pkg.*, pkgset_name, pkgset_date, pkg_hash
FROM last_pkgsets ALL
         INNER JOIN ( SELECT * FROM all_packages_with_source ) AS pkg USING (pkg_hash);

-- view to get last list from ACL
CREATE
OR REPLACE VIEW last_acl AS
SELECT acl_branch, max(acl_date) AS acl_date_last, any(acl_for) AS acl_for, argMax(acl_list, acl_date) AS acl_list
FROM Acl
GROUP BY Acl.acl_branch, Acl.acl_for;

-- view to prepare source packages with array of binary packages
CREATE
OR REPLACE VIEW source_with_binary_array_packages AS
SELECT DISTINCT pkg_hash,
                any(pkg_name)                AS pkgname,
                any(pkg_version)             AS version,
                any(pkg_release)             AS release,
                any(pkg_changelog)           AS changelog,
                groupUniqArray(name_evr) AS binlist
FROM Packages_buffer
         LEFT JOIN ( SELECT concat(pkg_name, ':', pkg_version, ':', pkg_release) AS name_evr, pkg_sourcerpm AS sourcerpm
                     FROM Packages_buffer
                     WHERE (pkg_sourcepackage = 0)
                       AND (pkg_name NOT LIKE '%-debuginfo')
                       AND (pkg_name NOT LIKE 'i586-%') ) AS Bin ON Bin.sourcerpm = pkg_filename
WHERE pkg_sourcepackage = 1
GROUP BY pkg_hash;

-- VIEW to get all pkghash with a unique array of pkgset names

CREATE VIEW all_source_pkghash_with_uniq_branch_name (pkg_hash UInt64, pkgset_array Array(String)) AS
SELECT pkg_hash, groupUniqArray(pkgset_name) AS pkgset_array
FROM all_pkgsets_sources
GROUP BY pkg_hash;

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

-- all pkgset's with date, name and pkghash
CREATE
OR REPLACE VIEW all_pkgsets
AS
SELECT pkg_hash, pkgset_name, date AS pkgset_date
FROM PackageSet_buffer
         RIGHT JOIN ( SELECT pkgset_uuid, pkgset_name, pkgset_date AS date FROM PackageSetName ) AS PkgSet USING (pkgset_uuid);

-- all packages from all assignments
CREATE
OR REPLACE VIEW all_packages AS
SELECT pkg.*, pkgset_name, pkgset_date, pkg_hash
FROM all_pkgsets ALL
         INNER JOIN ( SELECT * FROM Packages_buffer ) AS pkg USING (pkg_hash);

-- view for cve-check-tool with source, array of binary packages and changelogs.

CREATE
OR REPLACE VIEW packages_for_cvecheck AS
SELECT pkg_hash, pkg_name, pkg_version, pkg_release, binlist, pkgset_array, changelog
FROM Package
         LEFT JOIN ( SELECT source_with_binary_array_packages.*, SrcSet.pkgset_array
                     FROM source_with_binary_array_packages
                              LEFT JOIN ( SELECT * FROM all_source_pkghash_with_uniq_branch_name ) AS SrcSet
                                        USING (pkg_hash) ) AS Pkgs USING (pkg_hash)
WHERE sourcepackage = 1

