CREATE TABLE AssigmentName (
	id bigserial PRIMARY KEY,
	name varchar,
	datetime_release timestamp,
	tag varchar,

	UNIQUE(name, datetime_release)
);

CREATE INDEX ON AssigmentName (name);

CREATE TABLE Task (
	id bigserial PRIMARY KEY,			-- идентификатор записи
	task_id integer NOT NULL,			-- номер таска в сборочнице
	try integer NOT NULL,
	iteration integer NOT NULL,
	status varchar NOT NULL,
	is_test boolean NOT NULL,			-- тестовая сборка
	branch varchar NOT NULL
);

CREATE TABLE Packager (
	id bigserial PRIMARY KEY,
	name varchar NOT NULL,
	email varchar NOT NULL
);

CREATE INDEX ON Packager (name, email);

CREATE TABLE Arch (
	id bigserial PRIMARY KEY,
	name varchar UNIQUE
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

	FOREIGN KEY (task_id) REFERENCES Task (id),
	FOREIGN KEY (packager_id) REFERENCES Packager (id),
	FOREIGN KEY (arch_id) REFERENCES Arch (id)
);

CREATE INDEX ON Package (name);
CREATE INDEX ON Package (version);
CREATE INDEX ON Package (name, version);
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

CREATE TABLE FileName (
	id bigserial PRIMARY KEY,
	name varchar UNIQUE
);

CREATE INDEX ON FileName (name);

CREATE TABLE File (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_id bigint,
	filename_id bigint,				-- имя и путь установки
	filesize bigint,				-- размер файла
	filemode integer,				-- права доступа к файлу
	filerdev integer,
	filemtime timestamp,			-- время последней модификации файла в момент сборки пакета
	filemd5 varchar,				-- контрольная сумма MD5
	filelinkto varchar,				-- текст символьной ссылки
	fileflag integer,				-- тип файла: документация, конфигурационный файл, другое
	fileusername varchar,			-- владелец в символьном виде
	filegroupname varchar,			-- группа в символьном виде
	fileverifyflag bigint,
	filedevice bigint,
	fileinode bigint,
	filelang varchar,
	fileclass varchar,
	dirindex integer,
	basename varchar,

	FOREIGN KEY (package_id) REFERENCES Package (id),
	FOREIGN KEY (filename_id) REFERENCES File (id)
);

CREATE INDEX ON File (package_id);
CREATE INDEX ON File (filemd5);

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
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_id) REFERENCES Package (id)
);

CREATE INDEX ON Conflict (package_id);

CREATE TABLE Obsolete (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_id) REFERENCES Package (id)
);

CREATE INDEX ON Obsolete (package_id);

CREATE TABLE Provide (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_id) REFERENCES Package (id)
);

CREATE INDEX ON Provide (package_id);

CREATE TABLE Config (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	key varchar,					-- ключ
	value varchar					-- значение
);

INSERT INTO Config (key, value) VALUES ('DBVERSION', '0');
