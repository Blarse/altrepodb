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
	buildtime timestamp NOT NULL,		-- время создания таска
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

CREATE TABLE Package (
	sha1header varchar(40) PRIMARY KEY,
	packager_id bigint,
	task_id bigint,
	subtask integer,
	name varchar,
	arch varchar,
	version varchar,
	release varchar,
	epoch integer,
	serial_ integer,
	summary text,
	description text,
	changelog text,
	buildtime bigint,
	buildhost varchar,
	size bigint,
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
	archivesize bigint,
	rpmversion varchar,
	preinprog text ARRAY,
	postinprog text ARRAY,
	preunprog text ARRAY,
	postunprog text ARRAY,
	buildarchs varchar ARRAY,
	verifyscript text,
	verifyscriptprog text ARRAY,
	cookie varchar,
	prefixes varchar ARRAY,
	instprefixes varchar ARRAY,
	sourcepackage boolean,
	optflags varchar,
	disturl varchar,
	payloadformat varchar,
	payloadcompressor varchar,
	payloadflags varchar,
	platform varchar,
	disttag varchar,
	sourcerpm varchar,
	filename varchar,

	FOREIGN KEY (task_id) REFERENCES Task (id),
	FOREIGN KEY (packager_id) REFERENCES Packager (id)
);

CREATE INDEX ON Package (name);
CREATE INDEX ON Package (version);
CREATE INDEX ON Package (name, version);

CREATE TABLE Assigment (
	id bigserial PRIMARY KEY,
	assigmentname_id bigint,
	package_sha1 varchar(40),

	FOREIGN KEY (assigmentname_id) REFERENCES AssigmentName (id),
	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE INDEX ON Assigment (assigmentname_id);
CREATE INDEX ON Assigment (package_sha1);
CREATE INDEX ON Assigment (assigmentname_id, package_sha1);

CREATE TABLE File (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_sha1 varchar(40),
	filename varchar,				-- имя и путь установки
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

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE INDEX ON File (filename);
CREATE INDEX ON File (package_sha1);

CREATE TABLE Require (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_sha1 varchar(40),
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE INDEX ON Require (package_sha1);

CREATE TABLE Conflict (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_sha1 varchar(40),
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE INDEX ON Conflict (package_sha1);

CREATE TABLE Obsolete (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_sha1 varchar(40),
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE INDEX ON Obsolete (package_sha1);

CREATE TABLE Provide (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	package_sha1 varchar(40),
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE INDEX ON Provide (package_sha1);

-- Таблица для контроля версий схемы базы данных
CREATE TABLE SchemaControl (
	id bigserial PRIMARY KEY,		-- идентификатор записи
	filename varchar,				-- имя файла миграции
	version integer,				-- инкрементальная версия миграции
	description text,				-- описание миграции
	datatime_change timestamp		-- время внесения изменений
);

INSERT INTO SchemaControl (filename, version, description, datatime_change) 
VALUES ('0000_initial.sql', 0, 'Make the initial state of the database', now());
