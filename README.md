# ALTRepo Uploader

ALTRepo Uploader (a.k.a ALTRepoDB) is a set of tools that used to uploading data about ALT Linux distributions to Clickhouse database.

Database contents is used to maintain ALT Linux development and analytics with ALTRepo API.

# License

[GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0-standalone.html)

# Dependencies

ALTRepo Uploader requires Python version 3.7 or higher.

ALTRepo Uploader requires following packages installed for tools to be full functional.

**Note**: some package names are ALT Linux specific

## System packages
- xz
- git
- fuseiso
- gostsum
- squashfuse
- cdrkit-utils
- libvirt
- qemu-img
- qemu-kvm
- libguestfs
- guestfs-data

## Python packages
- python3-module-rpm
- python3-module-mmh3
- python3-module-requests
- python3-module-libarchive-c
- python3-module-beautifulsoup4
- python3-module-clickhouse-driver

# Database structure

ALTRepo Uploader uses Clickhouse as DBMS due to it's high performance and convenience for analytics.

## Database structure initialization

Initial database structure is stored in `sql/0000-initial.sql` file and could be deployed at Clickhouse server with following command:

    [user@host]$ cat sql/0000_initial.sql | clickhouse-client -h %SEREVR_IP_OR_DNS_NAME% -d %DATABASE_NAME% -n

## Database contents initialization

Some additional initialization data included as well. For example license name aliases could be uploaded with:

    [user@host]$ cat sql/license_aliases.json | clickhouse-client  -h %SEREVR_IP_OR_DNS_NAME% -d %DATABASE_NAME% --query="INSERT INTO LicenseAliases FORMAT JSONEachRow"

## Database permissions

It is necessary to set proper permissions for database user that will be used by utilities for connection.
At least it is neccessary to grant read and write permissions for all created tables and  full permissions for temporary tables.


# ALTRepo Uploader utilities

Most of provided CLI tools has pretty common set of arguments. All of them have at least `-h` option that displays the usage message.

## Configuration file

All CLI tools supports configuration provided by file with `-c, --config` option. Configuration file example is `config.ini.example`.

```
[DEFAULT]
workers=10              # number of threads (if used by utility)

[LOGGING]
log_to_file=no          # controls logging to file
log_to_syslog=no        # controls logging to syslog
log_to_console=yes      # controls logging to console [stderr]
syslog_ident=altrepodb  # controls syslog identity

[DATABASE]
dbname=repodb           # database name
host=localhost          # Clickhouse server IP address
port=9000               # Clickhouse server port
user=default            # databse user name
password=               # database user password
```
**Note**: Only logging level could be managed by CLI options. Logging handlers are controlled only by configuration file.

## Command line tools

### repo_loader
The utility uploads content of branch's repository state from file system to database.
Check the usage message with command:

    [user@host]$ python3 repo_loader.py -h

Usage example:

    [user@host]$ python3 repo_loader.py sisyphus /archive/repo/sisyphus/date/2021/08/18 --date 2021-08-18 -c config.ini --tag test_load -v

### task_loader
The utility uploads content of building task state from file system to database.
Check the usage message with command:

    [user@host]$ python3 task_loader.py -h

Usage example:

    [user@host]$ python3 task_loader.py /archive/tasks/done/_276/283337 -c config.ini -f -D

### iso_loader
The utility uploads content of ALT Linux distribution ISO image to database.
Check the usage message with command:

    [user@host]$ python3 iso_loader.py -h

Usage example:

    [user@host]$ python3 iso_loader.py alt-workstation-10.0-x86_64.iso --edition alt-workstation --version 10.0.0 --release release --platform "" --variant install --flavor "" --arch x86_64 --branch p10 --date 2022-04-04 --url http://ftp.altlinux.org/%PATH_TO_IMAGE% -c config.ini --debug

### image_loader
The utility uploads content of ALT Linux distribution image in TAR, IMG, QCOW2 formats to database.
Check the usage message with command:

    [user@host]$ python3 image_loader.py -h

Usage example:

    [user@host]$ python3 image_loader.py alt-p10-opennebula-x86_64.qcow2 --branch p10 --edition cloud --version 10.0.0 --release release --platform "" --variant install --flavor opennebula --arch x86_64 --date 2022-02-10 --url "http://ftp.altlinux.org/%PATH_TO_IMAGE%" --type qcow -c config.ini --debug

### acl_loader
The utility uploads ALT Linux maintaners ACLs to database.
Check the usage message with command:

    [user@host]$ python3 acl_loader.py -h

### beehive_loader
The utility uploads Beehive packages build results to database.
Check the usage message with command:

    [user@host]$ python3 beehive_loader.py -h

### bugzilla
The utility uploads Bugzilla issues to database.
Check the usage message with command:

    [user@host]$ python3 bugzilla.py -h

### repocop_loader
The utility uploads Repocop packages inspection to database.
Check the usage message with command:

    [user@host]$ python3 repocop_loader.py -h

### watch_loader
The utility uploads package's versions updates from Watch to database.
Check the usage message with command:

    [user@host]$ python3 watch_loader.py -h

### spdx_loader
The utility uploads licenses information from SPDX Git repository to database.
Check the usage message with command:

    [user@host]$ python3 spdx_loader.py -h

# Code style

Now project uses `black` for code formatting and `flake8` as a linter with configuration defined in `setup.cfg` file.

# Afternote

ALTRepo Uploader is under continuous development.

Functionality, database and code structure changes rapidly.

Check changelog and Git history for details.
