CREATE TABLE AssigmentName (
	id bigserial PRIMARY KEY,
	name varchar,
	datetime_release timestamp,
	tag varchar,
	complete boolean DEFAULT false,

	UNIQUE(name, datetime_release)
);

CREATE INDEX ON AssigmentName (name);

CREATE TABLE Task (
	id bigserial PRIMARY KEY,
	task_id integer NOT NULL,
	try integer NOT NULL,
	iteration integer NOT NULL,
	status varchar NOT NULL,
	is_test boolean NOT NULL,
	branch varchar NOT NULL
);

CREATE TABLE Packager (
	id bigserial PRIMARY KEY,
	name varchar NOT NULL,
	email varchar NOT NULL,
	UNIQUE (name, email)
);

CREATE TABLE Arch (
	id bigserial PRIMARY KEY,
	value varchar UNIQUE
);

CREATE TABLE Package (
	id bigserial PRIMARY KEY,
	sha1header varchar(40) UNIQUE,
	packager_id bigint,
	task_id bigint,
	subtask integer,
	name varchar,
	arch_id bigint,
	version varchar,
	release varchar,
	epoch integer,
	serial_ integer,
	buildtime bigint,
	buildhost varchar,
	size bigint,
	archivesize bigint,
	rpmversion varchar,
	cookie varchar,
	sourcepackage boolean,
	disttag varchar,
	sourcerpm varchar,
	filename varchar,
	sha1srcheader varchar(40),
	complete boolean DEFAULT false,

	FOREIGN KEY (task_id) REFERENCES Task (id),
	FOREIGN KEY (packager_id) REFERENCES Packager (id),
	FOREIGN KEY (arch_id) REFERENCES Arch (id)
);

CREATE INDEX ON Package (name);
CREATE INDEX ON Package (version);
CREATE INDEX ON Package (name, version);
CREATE INDEX ON Package (sha1header);
CREATE INDEX ON Package (sha1srcheader);


CREATE TABLE PackageInfo (
	id bigserial PRIMARY KEY,
	package_id bigint,
	summary text,
	description text,
	changelog text,
	distribution varchar,
	vendor varchar,
	gif bytea,
	xpm bytea,
	license varchar,
	group_ varchar,
	source varchar ARRAY,
	patch varchar ARRAY,
	url varchar,
	os varchar,
	prein text,
	postin text,
	preun text,
	postun text,
	icon bytea,
	preinprog text ARRAY,
	postinprog text ARRAY,
	preunprog text ARRAY,
	postunprog text ARRAY,
	buildarchs varchar ARRAY,
	verifyscript text,
	verifyscriptprog text ARRAY,
	prefixes varchar ARRAY,
	instprefixes varchar ARRAY,
	optflags varchar,
	disturl varchar,
	payloadformat varchar,
	payloadcompressor varchar,
	payloadflags varchar,
	platform varchar,

	FOREIGN KEY (package_id) REFERENCES Package (id)
);


CREATE TABLE Assigment (
	id bigserial PRIMARY KEY,
	assigmentname_id bigint,
	package_id bigint,

	FOREIGN KEY (assigmentname_id) REFERENCES AssigmentName (id),
	FOREIGN KEY (package_id) REFERENCES Package (id)
);

CREATE INDEX ON Assigment (assigmentname_id);
CREATE INDEX ON Assigment (package_id);
CREATE INDEX ON Assigment (assigmentname_id, package_id);

CREATE TABLE PathName (
	id bigserial PRIMARY KEY,
	value varchar UNIQUE
);

CREATE INDEX ON PathName (value);

CREATE TABLE FileUserName (
	id bigserial PRIMARY KEY,
	value varchar UNIQUE
);

CREATE TABLE FileGroupName (
	id bigserial PRIMARY KEY,
	value varchar UNIQUE
);

CREATE TABLE FileLang (
	id bigserial PRIMARY KEY,
	value varchar UNIQUE
);

CREATE TABLE FileClass (
	id bigserial PRIMARY KEY,
	value varchar UNIQUE
);


CREATE TABLE FileInfo (
	id bigserial PRIMARY KEY,
	filemd5 varchar,
	filelinkto varchar,
	basename varchar,
	UNIQUE(filemd5, filelinkto, basename)
);


CREATE TABLE File (
	id bigserial PRIMARY KEY,
	package_id bigint,
	fileinfo_id bigint,
	pathname_id bigint,
	filesize bigint,
	filemode integer,
	filerdev integer,
	filemtime timestamp,
	fileflag integer,
	fileusername_id bigint,
	filegroupname_id bigint,
	fileverifyflag bigint,
	filedevice bigint,
	fileinode bigint,
	filelang_id bigint,
	fileclass_id bigint,
	dirindex integer,

	FOREIGN KEY (package_id) REFERENCES Package (id),
	FOREIGN KEY (fileinfo_id) REFERENCES FileInfo (id),
	FOREIGN KEY (pathname_id) REFERENCES PathName (id),
	FOREIGN KEY (fileusername_id) REFERENCES FileUserName (id),
	FOREIGN KEY (filegroupname_id) REFERENCES FileGroupName (id),
	FOREIGN KEY (filelang_id) REFERENCES FileLang (id),
	FOREIGN KEY (fileclass_id) REFERENCES FileClass (id)
);

CREATE INDEX ON File (package_id);

CREATE TABLE Require (
	id bigserial PRIMARY KEY,
	package_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_id) REFERENCES Package (id)
);

CREATE INDEX ON Require (package_id);

CREATE TABLE Conflict (
	id bigserial PRIMARY KEY,
	package_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_id) REFERENCES Package (id)
);

CREATE INDEX ON Conflict (package_id);

CREATE TABLE Obsolete (
	id bigserial PRIMARY KEY,
	package_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_id) REFERENCES Package (id)
);

CREATE INDEX ON Obsolete (package_id);

CREATE TABLE Provide (
	id bigserial PRIMARY KEY,
	package_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_id) REFERENCES Package (id)
);

CREATE INDEX ON Provide (package_id);

CREATE TABLE Config (
	id bigserial PRIMARY KEY,
	key varchar,
	value varchar
);

CREATE FUNCTION insert_smart (_tbl regclass, _val varchar) RETURNS bigint AS
$BODY$
DECLARE
result bigint;
BEGIN
	EXECUTE format('INSERT INTO %1$I (value) VALUES (%2$L) ON CONFLICT (value) DO UPDATE set value=EXCLUDED.value RETURNING id',_tbl,_val) into result;
RETURN result;
END;
$BODY$
LANGUAGE PLPGSQL;

-- filemd5 varchar,
-- 	filelinkto varchar,
-- 	basename varchar,

CREATE FUNCTION insert_fileinfo (_filemd5 varchar, _filelinkto varchar, _basename varchar) RETURNS bigint AS
$BODY$
DECLARE
result bigint;
BEGIN
	EXECUTE format('INSERT INTO FileInfo (filemd5, filelinkto, basename) VALUES (%1$L, %2$L, %3$L) ON CONFLICT (filemd5, filelinkto, basename) DO UPDATE set filemd5=EXCLUDED.filemd5, filelinkto=EXCLUDED.filelinkto, basename=EXCLUDED.basename RETURNING id', _filemd5, _filelinkto, _basename) into result;
RETURN result;
END;
$BODY$
LANGUAGE PLPGSQL;


CREATE OR REPLACE FUNCTION insert_file (
package_id bigint, pathname_id bigint, filesize bigint, filemode integer, filerdev integer,
filemtime timestamp, filemd5 varchar, filelinkto varchar, fileflag integer, fileusername_id bigint, 
filegroupname_id bigint, fileverifyflag bigint, filedevice bigint, fileinode bigint, filelang_id bigint, 
fileclass_id bigint, dirindex integer, basename varchar) RETURNS bigint AS
$BODY$
INSERT INTO File (
    package_id, fileinfo_id, pathname_id, filesize, filemode, filerdev, filemtime,
    fileflag, fileusername_id, filegroupname_id, fileverifyflag, 
    filedevice, fileinode, filelang_id, fileclass_id, dirindex
    ) VALUES (
    package_id, insert_fileinfo(filemd5, filelinkto, basename), pathname_id, filesize, filemode, filerdev, filemtime,
    fileflag, fileusername_id, filegroupname_id, fileverifyflag, 
    filedevice, fileinode, filelang_id, fileclass_id, dirindex
    ) RETURNING id;

$BODY$
LANGUAGE SQL;

INSERT INTO Config (key, value) VALUES ('DBVERSION', '0');
