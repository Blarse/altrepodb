CREATE TABLE AssigmentName (
	uuid 				UUID,
	assigment_name 		String,
	assigment_date 		DateTime,
	tag 				String,
	complete 			UInt8
) 
ENGINE = MergeTree
ORDER BY (assigment_name, assigment_date, tag);


CREATE TABLE Tasks (
	task_id 		UInt32,
	subtask 		UInt32,
	sourcepkg_cs 	FixedString(40),
	try 			UInt16,
	iteration 		UInt8,
	status 			LowCardinality(String),
	is_test 		UInt8,
	branch 			LowCardinality(String),
	pkgs 			Array(FixedString(40)),
	userid 			LowCardinality(String),
	dir 			String,
	tag_name		String,
	tag_id			String,
	tag_author		LowCardinality(String),
	srpm			String,
	type			Enum8('srpm' = 0, 'gear' = 1),
	hash			String,
	task_arch		LowCardinality(String),
	chroot_base 	Array(FixedString(40)),
	chroot_BR 		Array(FixedString(40))
) 
ENGINE = MergeTree
ORDER BY (task_id, subtask,userid,status,branch,task_arch);


CREATE TABLE Assigment (
	uuid 		UUID,
	pkgcs 		FixedString(40)
) 
ENGINE = MergeTree
ORDER BY (uuid, pkgcs);


CREATE TABLE File (
	pkgcs 			FixedString(40),
	filename 		String,
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
	fileclass 		LowCardinality(String)
) 
ENGINE = MergeTree
ORDER BY (filename, pkgcs, filemd5, fileclass);


CREATE TABLE Package (
    pkgcs 				FixedString(40), 
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
ORDER BY (name, version,release,serial_, epoch, disttag, arch,packager,packager_email,replaceRegexpOne(sourcerpm, '-[0-9.]*-alt.*.src.rpm', ''),sha1srcheader,sourcerpm);


CREATE TABLE Depends (
	pkgcs 		FixedString(40),
	dpname 		String,
	dpversion 	String,
	flag 		UInt32,
	dptype 		Enum8('require' = 1, 'conflict' = 2, 'obsolete' = 3, 'provide' = 4)
)
ENGINE =  MergeTree
ORDER BY (pkgcs, dpname, dpversion, flag, dptype);


CREATE TABLE Config (
	key 		String,
	value 		String
)
ENGINE =  MergeTree
ORDER BY (key, value);


CREATE TABLE Assigment_buffer AS Assigment
ENGINE = Buffer(currentDatabase(), Assigment, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE File_buffer AS File
ENGINE = Buffer(currentDatabase(), File, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE Package_buffer AS Package
ENGINE = Buffer(currentDatabase(), Package, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);


CREATE TABLE Depends_buffer AS Depends
ENGINE = Buffer(currentDatabase(), Depends, 16, 10, 200, 10000, 1000000, 10000000, 1000000000);

CREATE OR REPLACE VIEW last_assigments AS SELECT pkgcs, assigment_name, date AS assigment_date FROM Assigment 
    RIGHT JOIN (SELECT argMax(uuid, assigment_date) AS uuid, assigment_name, max(assigment_date) 
    AS date FROM AssigmentName GROUP BY assigment_name) USING (uuid);

CREATE OR REPLACE VIEW last_packages AS SELECT pkg.*, assigment_name, assigment_date, pkgcs 
    FROM last_assigments ALL INNER JOIN (SELECT * FROM Package) AS pkg USING (pkgcs);

CREATE OR REPLACE VIEW last_depends AS SELECT Depends.*, pkgname, pkgversion, assigment_name, assigment_date, sourcepackage, arch
     FROM Depends ALL INNER JOIN (SELECT pkgcs, version AS pkgversion, assigment_name AS assigment_name, assigment_date, name 
     AS pkgname, sourcepackage,arch FROM last_packages) USING (pkgcs);
