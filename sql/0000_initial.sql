CREATE TABLE AssigmentName (
	id 					UUID,
	name 				String,
	datetime_release 	DateTime,
	tag 				String,
	complete 			UInt8
) 
ENGINE = MergeTree
ORDER BY (id, name, datetime_release, tag);


CREATE TABLE Tasks (
	id 				UInt32,
	subtask 		UInt32,
	sourcepkg_cs 	FixedString(40),
	try 			UInt16,
	iteration 		UInt8,
	status 			String,
	is_test 		UInt8,
	branch 			String,
	pkgs 			Array(FixedString(40))
) 
ENGINE = MergeTree
ORDER BY (id, subtask);


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
	fileusername 	String,
	filegroupname 	String,
	fileverifyflag 	UInt32,
	filedevice 		UInt32,
	filelang 		String,
	fileclass 		String
) 
ENGINE = MergeTree
ORDER BY (filename, pkgcs);


CREATE TABLE Package (
    pkgcs 				FixedString(40), 
    packager 			String, 
    packager_email 		String, 
    name 				String, 
    arch 				String, 
    version 			String, 
    release 			String, 
    epoch 				UInt16, 
    serial_ 			UInt16, 
    buildtime 			UInt32, 
    buildhost 			String, 
    size 				UInt64, 
    archivesize 		UInt64, 
    rpmversion 			String, 
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
    distribution 		String, 
    vendor 				String, 
    gif 				String, 
    xpm 				String, 
    license 			String, 
    group_ 				String, 
    url 				String, 
    os 					String, 
    prein 				String, 
    postin 				String, 
    preun 				String, 
    postun 				String, 
    icon 				String, 
    preinprog 			Array(String),
    postinprog 			Array(String),
    preunprog 			Array(String),
    postunprog 			Array (String),
    buildarchs 			Array (String),
    verifyscript 		String, 
    verifyscriptprog 	Array(String),
    prefixes 			Array(String),
    instprefixes 		Array(String),
    optflags 			String, 
    disturl 			String, 
    payloadformat 		String, 
    payloadcompressor 	String, 
    payloadflags 		String, 
    platform 			String
)
ENGINE = MergeTree
ORDER BY (pkgcs, name);


CREATE TABLE Depends (
	pkgcs 		FixedString(40),
	name 		String,
	version 	String,
	flag 		UInt32,
	dptype 		Enum8('require' = 1, 'conflict' = 2, 'obsolete' = 3, 'provide' = 4)
)
ENGINE =  MergeTree
ORDER BY (pkgcs, name, version, flag, dptype);


CREATE TABLE Config (
	key 		String,
	value 		String
)
ENGINE =  MergeTree
ORDER BY (key, value);


INSERT INTO Config (key, value) VALUES ('DBVERSION', '0');
