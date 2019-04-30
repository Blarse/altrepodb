CREATE TABLE IF NOT EXISTS AssigmentName (
	id bigserial PRIMARY KEY,
	name varchar,
	datetime_release timestamp,
	tag varchar
	UNIQUE(name, datetime_release)
);

CREATE TABLE IF NOT EXISTS Task (
	id bigserial PRIMARY KEY,			-- идендификатор записи
	task_id integer NOT NULL,			-- номер таска в сборочнице
	datetime_add timestamp NOT NULL,	-- время создания таска
	datetime_start timestamp,			-- время запуска таска
	datetime_end timestamp,				-- время окончания сборки
	status integer NOT NULL,
	is_test boolean,					-- тестовая сборка
	branch varchar NOT NULL
);

CREATE TABLE IF NOT EXISTS Packager (
	id bigserial PRIMARY KEY,
	name varchar NOT NULL,
	email varchar NOT NULL
);

CREATE INDEX ON Packager (name, email);

CREATE TABLE IF NOT EXISTS Package (
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

CREATE TABLE IF NOT EXISTS Assigment (
	id bigserial PRIMARY KEY,
	assigmentname_id bigint,
	package_sha1 varchar(40),

	FOREIGN KEY (assigmentname_id) REFERENCES AssigmentName (id),
	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE INDEX ON Assigment (assigmentname_id, package_sha1);

CREATE TABLE IF NOT EXISTS File (
	id bigserial PRIMARY KEY,		-- идендификатор записи
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

CREATE TABLE IF NOT EXISTS Require (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_sha1 varchar(40),
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE TABLE IF NOT EXISTS Conflict (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_sha1 varchar(40),
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE TABLE IF NOT EXISTS Obsolete (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_sha1 varchar(40),
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);

CREATE TABLE IF NOT EXISTS Provide (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_sha1 varchar(40),
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_sha1) REFERENCES Package (sha1header)
);
