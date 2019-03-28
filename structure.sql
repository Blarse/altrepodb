CREATE TABLE IF NOT EXISTS Assigment (
	id bigserial PRIMARY KEY,
	name varchar
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

CREATE TABLE IF NOT EXISTS PackageSrc (
	id bigserial PRIMARY KEY,
	assigment_id bigint,
	task_id bigint,
	packager_id bigint,
	name varchar,
	size bigint,
	changelog text,

	FOREIGN KEY (assigment_id) REFERENCES Assigment (id),
	FOREIGN KEY (task_id) REFERENCES Task (id),
	FOREIGN KEY (packager_id) REFERENCES Packager (id)
);

CREATE TABLE IF NOT EXISTS FileSrc (
	id bigserial PRIMARY KEY,			-- идендификатор записи
	package_src_id bigint NOT NULL,
	filename varchar,				-- имя и путь установки
	filesize bigint,				-- размер файла
	filemode bytea,				-- права доступа к файлу
	filemtime timestamp,			-- время последней модификации файла в момент сборки пакета
	filemd5 varchar,				-- контрольная сумма MD5
	fileusername varchar,			-- владелец в символьном виде
	filegroupname varchar,			-- группа в символьном виде

	FOREIGN KEY (package_src_id) REFERENCES PackageSrc (id)
);

CREATE TABLE IF NOT EXISTS BuildDependency (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_src_id bigint,
	name varchar,
	version varchar,
	flag integer,					-- флаги, определяющие как пакет зависит от возможностей других пакетов, например, версия не ниже указанной

	FOREIGN KEY (package_src_id) REFERENCES PackageSrc (id)
);

CREATE TABLE IF NOT EXISTS PackageBin (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	assigment_id bigint,
	package_src_id bigint,
	name varchar,
	arch varchar,
	version varchar,
	release varchar,
	epoch integer,
	serial_ integer,
	summary text,
	description text,
	buildtime bigint,
	buildhost varchar,
	size bigint,
	distribution varchar,
	vendor varchar,
	gif bytea,
	xpm bytea,
	license varchar,
	copyright varchar,
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
	sourcepackage integer,
	optflags varchar,
	disturl varchar,
	payloadformat varchar,
	payloadcompressor varchar,
	payloadflags varchar,
	platform varchar,
	sourcepkgid bytea,
	disttag varchar,

	FOREIGN KEY (assigment_id) REFERENCES Assigment (id),
	FOREIGN KEY (package_src_id) REFERENCES PackageSrc (id)
);

CREATE TABLE IF NOT EXISTS FileBin (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_bin_id bigint,
	filename varchar,				-- имя и путь установки
	filesize bigint,				-- размер файла
	filestate smallint,				-- состояние файла: normal, replaced другим пакетом, not installed, net shared
	filemode bytea,				-- права доступа к файлу
	filerdev bytea,
	filemtime timestamp,			-- время последней модификации файла в момент сборки пакета
	filemd5 varchar,				-- контрольная сумма MD5
	filelinkto varchar,				-- текст символьной ссылки
	fileflag integer,				-- тип файла: документация, конфигурационный файл, другое
	fileusername varchar,			-- владелец в символьном виде
	filegroupname varchar,			-- группа в символьном виде
	fileverifyflag integer,
	filedevice integer,
	fileinode integer,
	filelang varchar,
	filecolor integer,
	fileclass integer,
	dirindex integer,
	basename varchar,
	dirname varchar,

	FOREIGN KEY (package_bin_id) REFERENCES PackageBin (id)
);

CREATE TABLE IF NOT EXISTS Require (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_bin_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_bin_id) REFERENCES PackageBin (id)
);

CREATE TABLE IF NOT EXISTS Conflict (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_bin_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_bin_id) REFERENCES PackageBin (id)
);

CREATE TABLE IF NOT EXISTS Obsolete (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_bin_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_bin_id) REFERENCES PackageBin (id)
);

CREATE TABLE IF NOT EXISTS Provide (
	id bigserial PRIMARY KEY,		-- идендификатор записи
	package_bin_id bigint,
	name varchar,
	version varchar,
	flag integer,

	FOREIGN KEY (package_bin_id) REFERENCES PackageBin (id)
);
