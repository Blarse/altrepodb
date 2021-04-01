/*Stores packages hashes:
pkgh_mmh        MurMurHash from 'pkgh_sha1'
pkgh_md5        MD5 form packgae file
pkgh_sha1       SHA1 from package header
pkgh_sha256     SHA256 from package file

'pkgh_mmh' is equal to Packages 'pkg_hash' field
*/

CREATE TABLE PackageHash
(
    pkgh_mmh        UInt64,
    pkgh_md5        FixedString(16),
    pkgh_sha1       FixedString(20),
    pkgh_sha256     FixedString(32)
) ENGINE ReplacingMergeTree ORDER BY (pkgh_mmh, pkgh_md5, pkgh_sha256) PRIMARY KEY pkgh_mmh;

CREATE TABLE PackageHash_buffer AS PackageHash ENGINE = Buffer(currentDatabase(), PackageHash, 16, 10, 100, 10000, 1000000, 1000000, 100000000);

/*View that represent hashes in human readable format*/

CREATE
OR REPLACE VIEW PackageHash_view AS
SELECT pkgh_mmh, lower(hex(pkgh_md5)) as pkgh_md5, lower(hex(pkgh_sha1)) as pkgh_sha1, lower(hex(pkgh_sha256)) as pkgh_sha256
FROM  PackageHash_buffer;


/*Stores repository structure as tree linked by 'pkgset_uuid' and 'pkgset_puuid'.
Repository tree root has 'pkgset_puuid' = '00000000-0000-0000-0000-000000000000',
'pkgset_ruuid' is inherited from root and 'pkgset_depth' is set according to leaf path length.
'pkgset_kv' contains list of key:value pairs for various data.

Regular repository structure example:

'root' 'name'    'date'      'depth' 'uuid'      'puuid'     'ruuid'
[repo]:[sisyphus, 2021-03-25, 0,     'deadbeef', '00000000', 'deadbeef']
  |
  |   'arch' 'name'    'date'      'depth' 'uuid'      'puuid'     'ruuid'
  |-> [srpm]:[sisyphus, 2021-03-25, 1,     'feed0000', 'deadbeef', 'deadbeef']
  |
  |   'arch'   'name'    'date'      'depth' 'uuid'      'puuid'     'ruuid'
  |-> [x86_64]:[sisyphus, 2021-03-25, 1,     '01234567', 'deadbeef', 'deadbeef']
  |     |
  *     |   'comp'    'name'    'date'      'depth' 'uuid'      'puuid'     'ruuid'
  *     |-> [classic]:[sisyphus, 2021-03-25, 2,     'aabbccdd', '01234567', 'deadbeef']
  *            *
  *            *
  *         'comp'         'name'    'date'      'depth' 'uuid'      'puuid'     'ruuid'
  *     |-> [checkinstall]:[sisyphus, 2021-03-25, 2,     'eeff1122', '01234567', 'deadbeef']
  *
  *
  |   'arch' 'name'    'date'      'depth' 'uuid'      'puuid'     'ruuid'
  |-> [armh]:[sisyphus, 2021-03-25, 1,     '55556677', 'deadbeef', 'deadbeef']
         |
         |   'comp'    'name'    'date'      'depth' 'uuid'      'puuid'     'ruuid'
         |-> [classic]:[sisyphus, 2021-03-25, 2,     '98765432', '55556677', 'deadbeef']
         *
         *
         |    'comp'         'name'    'date'      'depth' 'uuid'      'puuid'     'ruuid'
         |->  [checkinstall]:[sisyphus, 2021-03-25, 2,     'cc00bb00', '55556677', 'deadbeef']
 */

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


/*Stores repository for 'srpm' and every component
Logically linked to PackageSetName table by 'pkgset_uuid' field*/

CREATE TABLE PackageSet
(
    pkgset_uuid     UUID CODEC(ZSTD(1)),
    pkg_hash        UInt64 CODEC(Gorilla,ZSTD(1))
) ENGINE = MergeTree ORDER BY (pkgset_uuid, pkg_hash) PRIMARY KEY (pkgset_uuid);

CREATE TABLE PackageSet_buffer AS PackageSet ENGINE = Buffer(currentDatabase(), PackageSet, 16, 10, 100, 10000, 1000000, 1000000, 100000000);


/*Stores information about packages gathered from RPM header
Files for package are stored in separate Files table
Changelog texts are stored separately, linked by MurMurHash from text contents*/

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


/*Stores information about files gathered from package RPM header
Logically linked to Packages table by 'pkg_hash' field*/

CREATE TABLE Files
(
    pkg_hash        UInt64,
    file_name       String,
    file_hashname   UInt64 MATERIALIZED murmurHash3_64(file_name),
    file_hashdir    UInt64 MATERIALIZED murmurHash3_64(arrayStringConcat(arrayPopBack(splitByChar('/', file_name)))),
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
) ENGINE = ReplacingMergeTree ORDER BY (pkg_hash, file_name, file_class, file_md5) PRIMARY KEY pkg_hash;


CREATE TABLE Files_buffer AS Files ENGINE = Buffer(currentDatabase(), Files, 16, 10, 200, 10000, 1000000, 10000000, 100000000);


/*Stores information about package dependencies for package.
Logically linked to Packages table by 'pkg_hash' field*/

CREATE TABLE Depends
(
    pkg_hash   UInt64,
    dp_name    String,
    dp_version String,
    dp_flag    UInt32,
    dp_type    Enum8('require' = 1, 'conflict' = 2, 'obsolete' = 3, 'provide' = 4)
) ENGINE = MergeTree ORDER BY (dp_name, dp_version, dp_type) PRIMARY KEY dp_name;


CREATE TABLE Depends_buffer AS Depends ENGINE = Buffer(currentDatabase(), Depends, 16, 10, 200, 10000, 1000000,
                                                10000000, 100000000);


/*Stores information about changelog texts gathered from package RPM header.
Only unique text records stored
Logically linked to Packages table by 'chlog_hash' field*/

CREATE TABLE Changelog
(
    chlog_hash  UInt64,
    chlog_text  String
) ENGINE = ReplacingMergeTree ORDER BY (chlog_hash, chlog_text) PRIMARY KEY chlog_hash;


CREATE TABLE Changelog_buffer AS Changelog ENGINE = Buffer(currentDatabase(), Changelog, 16, 10, 100, 10000, 1000000, 1000000, 100000000);


/* Last package sets */

CREATE
OR REPLACE VIEW repodb_test.last_pkgsets AS
SELECT
    *,
    pkgset_kv.v[indexOf(pkgset_kv.k, 'class')] AS pkgset_class
FROM repodb_test.PackageSetName
RIGHT JOIN
(
    SELECT
        argMax(pkgset_ruuid, pkgset_date) AS pkgset_ruuid,
        pkgset_nodename AS pkgset_name
    FROM repodb_test.PackageSetName
    WHERE pkgset_depth = 0
    GROUP BY pkgset_name
) AS RootPkgs USING (pkgset_ruuid) ORDER BY pkgset_name, pkgset_depth;
