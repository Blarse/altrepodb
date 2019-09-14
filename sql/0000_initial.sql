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

CREATE TABLE CveChecked (
    cveid	String,
    pkgname	String,
    checkdate	DateTime,
    description String
)
ENGINE =  MergeTree
ORDER BY (cveid,  pkgname, checkdate) PRIMARY KEY (cveid,pkgname);


CREATE TABLE AclGroup (
    aclgroup_date	DateTime,
    aclgroup	String,
    aclgroup_branch	String,
    acl_group	Array(String)
)
ENGINE =  MergeTree
ORDER BY (aclgroup_date, aclgroup_branch,aclgroup, acl_group) PRIMARY KEY (aclgroup_date,aclgroup_branch);


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


CREATE TABLE Assigment_buffer AS Assigment
ENGINE = Buffer(currentDatabase(), Assigment, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE File_buffer AS File
ENGINE = Buffer(currentDatabase(), File, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE Package_buffer AS Package
ENGINE = Buffer(currentDatabase(), Package, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE Depends_buffer AS Depends
ENGINE = Buffer(currentDatabase(), Depends, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);

CREATE OR REPLACE VIEW last_assigments AS SELECT pkghash, assigment_name, date AS assigment_date FROM Assigment_buffer
    RIGHT JOIN (SELECT argMax(uuid, assigment_date) AS uuid, assigment_name, max(assigment_date) 
    AS date FROM AssigmentName GROUP BY assigment_name) USING (uuid);

CREATE OR REPLACE VIEW last_packages AS SELECT pkg.*, assigment_name, assigment_date, pkghash 
    FROM last_assigments ALL INNER JOIN (SELECT * FROM Package_buffer) AS pkg USING (pkghash);

CREATE OR REPLACE VIEW last_depends AS SELECT Depends_buffer.*, pkgname, pkgversion, assigment_name, assigment_date, sourcepackage, arch, filename, sourcerpm
     FROM Depends_buffer ALL INNER JOIN (SELECT pkghash, version AS pkgversion, assigment_name AS assigment_name, assigment_date, name AS pkgname,
     sourcepackage, arch, filename, sourcerpm FROM last_packages) USING (pkghash);

-- view to get joined list packages with sourcepackage

CREATE OR REPLACE VIEW last_packages_with_source AS SELECT last_packages.*, srcPackage.* FROM last_packages 
    LEFT JOIN (  SELECT  pkghash AS sourcepkghash,  name AS sourcepkgname, filename AS sourcerpm FROM last_packages WHERE sourcepackage = 1)
     AS srcPackage USING (sourcerpm) WHERE sourcepackage = 0;

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

