import argparse
import configparser
import os
import re
import clickhouse_driver as chd
import subprocess

SQL_DIR = './sql'
filename_pattern = re.compile('\d{4}_[a-z0-9\-]+\.sql')


def get_client(args):
    return chd.Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password
    )


def scan_migration_files():
    files = [i for i in os.listdir(SQL_DIR)]
    return files


def get_file_version(f):
    return int(f.split('_')[0])


def get_current_version(files):
    if not files:
        raise ValueError('SQL files not found')
    v = max(get_file_version(i) for i in files)
    return v


def get_actual_version(conn):
    sql = "SELECT MAX(value) FROM Config WHERE key='DBVERSION'"
    result = conn.execute(sql)
    if result:
        return int(result[0][0])
    return -1


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-U', '--update', action='store_true', help='Update database schema to actual state')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database password')
    parser.add_argument('-u', '--user', type=str, help='Database login')
    parser.add_argument('-P', '--password', type=str, help='Database password')
    return parser.parse_args()


def set_config(args):
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        if cfg.has_section('DATABASE'):
            section_db = cfg['DATABASE']
            args.dbname = args.dbname or section_db.get('dbname', 'default')
            args.host = args.host or section_db.get('host', 'localhost')
            args.port = args.port or section_db.get('port', None)
            args.user = args.user or section_db.get('user', 'default')
            args.password = args.password or section_db.get('password', '')
    else:
        args.dbname = args.dbname or 'default'
        args.host = args.host or 'localhost'
        args.port = args.port or None
        args.user = args.user or 'default'
        args.password = args.password or ''
    return args


def update_all(conn, _args, files, actual_version):
    files.sort()
    for fname in files:
        file_version = get_file_version(fname)
        if file_version > actual_version:
            result = update(conn, _args, fname)
            if result:
                actual_version += 1


def update(conn, _args, fname):
    version = get_file_version(fname)
    fname = os.path.join(SQL_DIR, fname)
    args = ['clickhouse-client', '-n']
    args.extend(['--database', _args.dbname])
    args.extend(['--host', _args.host])
    args.extend(['--user', _args.user])
    if _args.port:
        args.extend(['--port', _args.port])
    if _args.password:
        args.extend(['--password', _args.password])
    f = None
    try:
        f = os.open(fname, os.O_RDONLY)
        result = subprocess.run(args, stdout=subprocess.DEVNULL, stdin=f)
        result.check_returncode()
        conn.execute(
            'INSERT INTO Config (key, value) VALUES',
            [{'key': 'DBVERSION', 'value': str(version)}]
        )
    except Exception as e:
        print('update error: {0}, {1}'.format(fname, str(e)))
        return False
    else:
        print('update: {0}'.format(fname))
        return True
    finally:
        if f:
            os.close(f)


def check_latest_version(conn):
    current_version = get_current_version(scan_migration_files())
    actual_version = get_actual_version(conn)
    return current_version == actual_version


def check_database(conn):
    result = conn.execute('EXISTS Config')
    return result[0][0]


def main():
    args = get_args()
    args = set_config(args)
    conn = get_client(args)

    if check_database(conn):
        actual_version = get_actual_version(conn)
    elif args.update:
        result = update(conn, args, '0000_initial.sql')
        if result:
            actual_version = get_actual_version(conn)
        else:
            print('Database initialisation failed ')
            conn.disconnect()
            return 1
    else:
        print('Database not initialised! Use key --update for initialisation')
        conn.disconnect()
        return 1

    migration_files = scan_migration_files()
    current_version = get_current_version(migration_files)

    print('Latest version in database: {0}'.format(actual_version))
    print('Latest version by files: {0}'.format(current_version))

    if args.update and current_version > actual_version:
        update_all(conn, args, migration_files, actual_version)
    elif current_version == actual_version:
        print('Nothing to update')
    conn.disconnect()


if __name__ == '__main__':
    main()
