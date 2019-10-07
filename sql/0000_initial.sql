CREATE TABLE AssigmentName (
	uuid 				UUID,
	assigment_name 		String,
	assigment_date 		DateTime,
	tag 				String,
	complete 			UInt8
)
ENGINE = MergeTree
ORDER BY (assigment_date, assigment_name) PRIMARY KEY assigment_date;


CREATE TABLE Tasks (
	task_id 		UInt32,
	subtask 		UInt32,
	sourcepkg_hash 	UInt64,
	try 			UInt16,
	iteration 		UInt8,
	status 			LowCardinality(String),
	is_test 		UInt8,
	branch 			LowCardinality(String),
	pkgs 			Array(UInt64),
	userid 			LowCardinality(String),
	dir 			String,
	tag_name		String,
	tag_id			String,
	tag_author		LowCardinality(String),
	srpm			String,
	type			Enum8('srpm' = 0, 'gear' = 1),
	hash			String,
	task_arch		LowCardinality(String),
	chroot_base 	Array(UInt64),
	chroot_BR 		Array(UInt64)
) 
ENGINE = MergeTree
ORDER BY (task_id, subtask,userid,status,branch,task_arch);


CREATE TABLE Assigment (
	uuid 		UUID,
	pkghash 	UInt64 CODEC(NONE)
) 
ENGINE = MergeTree
ORDER BY (uuid, pkghash) PRIMARY KEY (uuid);


CREATE TABLE File (
	pkghash			UInt64,
	filename 		String,
	hashname		UInt64 MATERIALIZED murmurHash3_64(filename) CODEC(NONE),
	hashdir 		UInt64 MATERIALIZED murmurHash3_64(arrayStringConcat(arrayPopBack(splitByChar('/', filename)))),
	filelinkto 		String,
	filemd5 		FixedString(32),
	filesize 		UInt32,
	filemode 		UInt16,
	filerdev 		UInt16,
	filemtime 		DateTime,
	fileflag 		UInt16,
	fileusername 	LowCardinality(String),
	filegroupname 	LowCardinality(String),
	fileverifyflag 	UInt32,
	filedevice 		UInt32,
	filelang 		LowCardinality(String),
	fileclass 		String
) 
ENGINE = MergeTree
ORDER BY (pkghash, filename, fileclass, filemd5) PRIMARY KEY pkghash;

CREATE TABLE UniqPkgs (
    pkg_hash 				UInt64 CODEC(NONE), 
    pkg_cs 				FixedString(40) CODEC(NONE), 
    pkg_filemd5 				FixedString(32) CODEC(NONE), 
    pkg_packager 			LowCardinality(String), 
    pkg_packager_email 		LowCardinality(String), 
    pkg_name 				String, 
    pkg_arch 				LowCardinality(String), 
    pkg_version 			String, 
    pkg_release 			String, 
    pkg_epoch 				UInt32, 
    pkg_serial 			UInt32, 
    pkg_buildtime 			UInt32, 
    pkg_buildhost 			LowCardinality(String), 
    pkg_size 				UInt64, 
    pkg_filesize 				UInt64, 
    pkg_archivesize 		UInt64, 
    pkg_rpmversion 			LowCardinality(String), 
    pkg_cookie 				String, 
    pkg_src 		UInt8, 
    pkg_disttag 			String, 
    pkg_sourcerpm 			String, 
    pkg_filename 			String, 
    pkg_src_cs 		FixedString(40), 
    pkg_summary 			String, 
    pkg_description 		String, 
    pkg_changelog 			String, 
    pkg_distribution 		LowCardinality(String), 
    pkg_vendor 				LowCardinality(String), 
    pkg_license 			LowCardinality(String), 
    pkg_group 				String, 
    pkg_url 				LowCardinality(String), 
    pkg_os 					LowCardinality(String), 
    pkg_prein 				String, 
    pkg_postin 				String, 
    pkg_preun 				String, 
    pkg_postun 				String, 
    pkg_preinprog 			Array(String),
    pkg_postinprog 			Array(String),
    pkg_preunprog 			Array(String),
    pkg_postunprog 			Array (String),
    pkg_buildarchs 			Array (LowCardinality(String)),
    pkg_verifyscript 		String, 
    pkg_verifyscriptprog 	Array(String),
    pkg_prefixes 			Array(LowCardinality(String)),
    pkg_instprefixes 		Array(String),
    pkg_optflags 			LowCardinality(String), 
    pkg_disturl 			String, 
    pkg_payloadformat 		LowCardinality(String), 
    pkg_payloadcompressor 	LowCardinality(String), 
    pkg_payloadflags 		LowCardinality(String), 
    pkg_platform 			LowCardinality(String)
)
ENGINE = MergeTree
ORDER BY (name,arch,version,release,serial_,epoch,disttag,filename, sourcerpm,packager,packager_email)
PRIMARY KEY (name,arch) SETTINGS index_granularity = 2048;

CREATE TABLE Package (
    pkghash 				UInt64 CODEC(NONE), 
    pkgcs 				FixedString(40) CODEC(NONE), 
    packager 			LowCardinality(String), 
    packager_email 		LowCardinality(String), 
    name 				String, 
    arch 				LowCardinality(String), 
    version 			String, 
    release 			String, 
    epoch 				UInt32, 
    serial_ 			UInt32, 
    buildtime 			UInt32, 
    buildhost 			LowCardinality(String), 
    size 				UInt64, 
    archivesize 		UInt64, 
    rpmversion 			LowCardinality(String), 
    cookie 				String, 
    sourcepackage 		UInt8, 
    disttag 			String, 
    sourcerpm 			String, 
    filename 			String, 
    sha1srcheader 		FixedString(40), 
    complete 			UInt8, 
    summary 			String, 
    description 		String, 
    changelog 			String, 
    distribution 		LowCardinality(String), 
    vendor 				LowCardinality(String), 
    gif 				String, 
    xpm 				String, 
    license 			LowCardinality(String), 
    group_ 				String, 
    url 				LowCardinality(String), 
    os 					LowCardinality(String), 
    prein 				String, 
    postin 				String, 
    preun 				String, 
    postun 				String, 
    icon 				String, 
    preinprog 			Array(String),
    postinprog 			Array(String),
    preunprog 			Array(String),
    postunprog 			Array (String),
    buildarchs 			Array (LowCardinality(String)),
    verifyscript 		String, 
    verifyscriptprog 	Array(String),
    prefixes 			Array(LowCardinality(String)),
    instprefixes 		Array(String),
    optflags 			LowCardinality(String), 
    disturl 			String, 
    payloadformat 		LowCardinality(String), 
    payloadcompressor 	LowCardinality(String), 
    payloadflags 		LowCardinality(String), 
    platform 			LowCardinality(String)
)
ENGINE = MergeTree
ORDER BY (name,arch,version,release,serial_,epoch,disttag,filename, sourcerpm,packager,packager_email)
PRIMARY KEY (name,arch) SETTINGS index_granularity = 2048;


CREATE TABLE Depends (
	pkghash 		UInt64,
	dpname 		String,
	dpversion 	String,
	flag 		UInt32,
	dptype 		Enum8('require' = 1, 'conflict' = 2, 'obsolete' = 3, 'provide' = 4)
)
ENGINE =  MergeTree
ORDER BY (pkghash, dptype, dpname, dpversion, flag) PRIMARY KEY pkghash;


CREATE TABLE Config (
	key 		String,
	value 		String
)
ENGINE =  MergeTree
ORDER BY (key, value);

CREATE TABLE Acl (
    acl_date	DateTime,
    acl_for	String,
    acl_branch	String,
    acl_list	Array(String)
)
ENGINE =  MergeTree
ORDER BY (acl_date, acl_branch, acl_for, acl_list) PRIMARY KEY (acl_date,acl_branch);

CREATE TABLE Cve (`pkghash` UInt64,
    `cveid` String,
    `cve_description` String,
    `url` String,
    `score` Float64,
    `attacktype` String,
    `status` Enum8('check' = 0,
    'patched' = 1),
    `uris` Array(String),
    `modifieddate` DateTime,
    `parsingdate` DateTime)
     ENGINE = MergeTree
    ORDER BY
    (pkghash, cveid, modifieddate,parsingdate)
    SETTINGS index_granularity = 8192;

CREATE TABLE CveAbsentPackages (`product_name` String,
    `cveid` String,
    `cve_description` String,
    `url` String,
    `score` Float64,
    `attacktype` String,
    `uris` Array(String),
    `modifieddate` DateTime,
    `parsingdate` DateTime)
     ENGINE = MergeTree
    ORDER BY
    (product_name, cveid, modifieddate, parsingdate)
    SETTINGS index_granularity = 8192;

CREATE TABLE FstecBduList (
    bdu_identifier                  String,
    bdu_name                        String,
    bdu_description                 String,
    bdu_identify_date               Date,
    bdu_severity                    String,
    bdu_solution                    String,
    bdu_vul_status                  String,
    bdu_exploit_status              String,
    bdu_fix_status                  String,
    bdu_sources                     String,
    bdu_other                       String,
    bdu_vulnerable_software Nested (
        vendor          String,
        type            Array(String),
        name            String,
        version         String
    ),
    bdu_environment Nested (
        vendor          String,
        version         String,
        name            String,
        platform        String
    ),
    bdu_cwe Nested (
        identifier      String
    ),
    bdu_cvss Nested (
        vector          String,
        score           Float32
    ),
    bdu_identifiers Nested (
        identifier      String,
        type            String,
        link            String
    )
) 
ENGINE = MergeTree
ORDER BY (bdu_identifier, bdu_identify_date, bdu_name) PRIMARY KEY (bdu_identifier, bdu_identify_date);

CREATE TABLE AptPkgRelease (
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
ENGINE = MergeTree
ORDER BY (apr_date, apr_tag, apr_suite, apr_arch, apr_version) PRIMARY KEY (apr_date, apr_tag, apr_suite, apr_arch);

CREATE TABLE AptPkgSet (
    apr_uuid        UUID,
    aps_uuid        UUID,
    aps_name        String,
    aps_version     String,
    aps_release     String,
    aps_epoch       UInt32, 
    aps_serial      UInt32,
    aps_buildtime   UInt32,
    aps_disttag     String,
    aps_arch        String,
    aps_sourcerpm   String,
    aps_md5         String,
    aps_filesize    UInt64,
    aps_filename    String
)
ENGINE = MergeTree
ORDER BY (apr_uuid, aps_md5, aps_sourcerpm, aps_filename) PRIMARY KEY (apr_uuid, aps_md5);

CREATE TABLE CveChecked (`cveid` String,
    `pkgname` String,
    `checkdate` DateTime,
    `description` String,
    `description_ru` String,
    `checked_ver.pkg_evr` Array(String),
    `checked_ver.pkg_branch` Array(String))
     ENGINE = MergeTree
     PRIMARY KEY (cveid,pkgname)
     ORDER BY
    (cveid, pkgname,checkdate)
     SETTINGS index_granularity = 8192;


CREATE TABLE Assigment_buffer AS Assigment
ENGINE = Buffer(currentDatabase(), Assigment, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE File_buffer AS File
ENGINE = Buffer(currentDatabase(), File, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE Package_buffer AS Package
ENGINE = Buffer(currentDatabase(), Package, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE Depends_buffer AS Depends
ENGINE = Buffer(currentDatabase(), Depends, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);

-- return pkghash, name and date for recent pkgset's

CREATE OR REPLACE VIEW last_assigments AS
SELECT 
    pkghash, 
    assigment_name, 
    date AS assigment_date
FROM Assigment_buffer
RIGHT JOIN 
(
    SELECT 
        argMax(uuid, assigment_date) AS uuid, 
        assigment_name, 
        max(assigment_date) AS date
    FROM AssigmentName
    GROUP BY assigment_name
) USING (uuid)
PREWHERE uuid IN 
(
    SELECT uuid
    FROM 
    (
        SELECT 
            argMax(uuid, assigment_date) AS uuid, 
            assigment_name, 
            max(assigment_date) AS date
        FROM AssigmentName
        GROUP BY assigment_name
    )
);

CREATE OR REPLACE VIEW last_packages AS SELECT pkg.*, assigment_name, assigment_date, pkghash 
    FROM last_assigments ALL INNER JOIN (SELECT * FROM Package_buffer) AS pkg USING (pkghash);

CREATE OR REPLACE VIEW last_depends AS SELECT Depends_buffer.*, pkgname, pkgversion, assigment_name, assigment_date, sourcepackage, arch, filename, sourcerpm
     FROM Depends_buffer ALL INNER JOIN (SELECT pkghash, version AS pkgversion, assigment_name AS assigment_name, assigment_date, name AS pkgname,
     sourcepackage, arch, filename, sourcerpm FROM last_packages) USING (pkghash);

-- VIEW to JOIN binary and source package

CREATE OR REPLACE VIEW all_packages_with_source AS
SELECT
    Package_buffer.*,
    srcPackage.*
FROM Package_buffer
LEFT JOIN
(
    SELECT
        pkghash AS sourcepkghash,
        name AS sourcepkgname,
        filename AS sourcerpm
    FROM Package_buffer
    WHERE sourcepackage = 1
) AS srcPackage USING (sourcerpm)
WHERE sourcepackage = 0;

-- view to JOIN all pkgset's for source packages
CREATE VIEW all_assigments_sources AS
SELECT
    pkghash,
    assigment_name,
    date AS assigment_date
FROM Assigment_buffer
RIGHT JOIN
(
    SELECT
        uuid,
        assigment_name,
        assigment_date AS date
    FROM AssigmentName
) USING (uuid)
PREWHERE pkghash IN
(
    SELECT pkghash
    FROM Package
    WHERE sourcepackage = 1
);

-- view to get joined list packages with sourcepackage
CREATE OR REPLACE VIEW last_packages_with_source AS
SELECT
    pkg.*,
    assigment_name,
    assigment_date,
    pkghash
FROM last_assigments
ALL INNER JOIN
(
    SELECT *
    FROM all_packages_with_source
) AS pkg USING (pkghash);

-- view to get last list from ACL
CREATE OR REPLACE VIEW last_acl AS
SELECT 
    acl_branch, 
    max(acl_date) AS acl_date_last, 
    any(acl_for) AS acl_for, 
    argMax(acl_list, acl_date) AS acl_list
FROM Acl
GROUP BY 
    Acl.acl_branch, 
    Acl.acl_for;

-- view to prepare source packages with array of binary packages
CREATE OR REPLACE VIEW source_with_binary_array_packages AS
SELECT DISTINCT
    pkghash,
    any(name) AS pkgname,
    any(version) AS version,
    any(release) AS release,
    any(changelog) AS changelog,
    groupUniqArray(name_evr) AS binlist
FROM Package_buffer
LEFT JOIN
(
    SELECT
        concat(name, ':', version, ':', release) AS name_evr,
        sourcerpm
    FROM Package_buffer
    WHERE (sourcepackage = 0) AND (name NOT LIKE '%-debuginfo') AND (name NOT LIKE 'i586-%')
) AS Bin ON Bin.sourcerpm = filename
WHERE sourcepackage = 1
GROUP BY pkghash;

-- VIEW to get all pkghash with a unique array of pkgset names

CREATE VIEW all_source_pkghash_with_uniq_branch_name
(
    `pkghash` UInt64,
    `pkgsetarray` Array(String)
) AS
SELECT
    pkghash,
    groupUniqArray(assigment_name) AS pkgsetarray
FROM all_assigments_sources
GROUP BY pkghash;

-- view to get expanded list ACLs from database with groups
CREATE OR REPLACE VIEW last_acl_with_groups AS
SELECT 
    acl_branch, 
    acl_date_last AS acl_date, 
    acl_for AS pkgname, 
    if(notEmpty(AclGroups.aclg), AclGroups.aclg, aclu) AS acl_user, 
    order_u, 
    AclGroups.order_g
FROM last_acl AS AclUsers
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
    FROM last_acl
    ARRAY JOIN 
        acl_list AS aclg, 
        arrayEnumerate(acl_list) AS order_g
    WHERE acl_for LIKE '@%'
) AS AclGroups ON (aclu = AclGroups.acl_for) AND (last_acl.acl_branch = AclGroups.acl_branch)
ORDER BY 
    order_u ASC, 
    order_g ASC;

-- view for all CVE's and packages
CREATE OR REPLACE VIEW last_cve AS
SELECT *
FROM Cve
LEFT JOIN last_packages USING (pkghash);

-- all pkgset's with date, name and pkghash
CREATE VIEW all_assigments
AS
SELECT
    pkghash,
    assigment_name,
    date AS assigment_date
FROM Assigment_buffer
RIGHT JOIN
(
    SELECT
        uuid,
        assigment_name,
        assigment_date AS date
    FROM AssigmentName
) USING (uuid);

-- all packages from all assigments
CREATE VIEW all_packages AS
SELECT
    pkg.*,
    assigment_name,
    assigment_date,
    pkghash
FROM all_assigments
ALL INNER JOIN
(
    SELECT *
    FROM Package_buffer
) AS pkg USING (pkghash);

-- view for cve-check-tool with source, array of binary packages and changelogs.

CREATE OR REPLACE VIEW packages_for_cvecheck AS
SELECT
    source_with_binary_array_packages.*,
    SrcSet.pkgsetarray
FROM source_with_binary_array_packages
LEFT JOIN
(
    SELECT *
    FROM all_source_pkghash_with_uniq_branch_name
) AS SrcSet USING (pkghash);

