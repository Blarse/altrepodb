import argparse
import configparser
import os
import re
import psycopg2

from utils import get_conn_str

SQL_DIR = './sql'
filename_pattern = re.compile('\d{4}_[a-z0-9\-]+\.sql')


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
    sql = "SELECT value FROM Config WHERE key='DBVERSION'"
    with conn.cursor() as cur:
        cur.execute(sql)
        result = cur.fetchone()
        if result:
            return int(result[0])


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
            args.dbname = args.dbname or section_db.get('dbname', None)
            args.host = args.host or section_db.get('host', None)
            args.port = args.port or section_db.get('port', None)
            args.user = args.user or section_db.get('user', None)
            args.password = args.password or section_db.get('password', None)
    return args


def update_all(conn, files, actual_version):
    files.sort()
    for fname in files:
        file_version = get_file_version(fname)
        if file_version > actual_version:
            result = update(conn, fname, file_version)
            if result:
                actual_version += 1


def update(conn, fname, file_version=None):
    try:
        with open(os.path.join(SQL_DIR, fname)) as f, conn.cursor() as cur:
            cur.execute(f.read())
            if file_version is not None:
                cur.execute(
                    "UPDATE Config SET value='%s' WHERE key='DBVERSION'",
                    (file_version,)
                )
    except Exception as e:
        print('update error: {0}, {1}'.format(fname, str(e)))
        return False
    else:
        print('update: {0}'.format(fname))
        return True


def check_latest_version(conn):
    current_version = get_current_version(scan_migration_files())
    actual_version = get_actual_version(conn)
    return current_version == actual_version


def main():
    args = get_args()
    args = set_config(args)
    conn = psycopg2.connect(get_conn_str(args))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    try:
        actual_version = get_actual_version(conn)
    except psycopg2.ProgrammingError:
        if args.update:
            result = update(conn, '0000_initial.sql')
            if result:
                actual_version = get_actual_version(conn)
            else:
                print('Database initialisation failed ')
                conn.close()
                return 1
        else:
            print('Database not initialised! Use key --update for initialisation')
            conn.close()
            return 1

    migration_files = scan_migration_files()
    current_version = get_current_version(migration_files)

    print('Latest version in database: {0}'.format(actual_version))
    print('Latest version by files: {0}'.format(current_version))

    if args.update and current_version > actual_version:
        update_all(conn, migration_files, actual_version)
    elif current_version == actual_version:
        print('Nothing to update')
    conn.close()


if __name__ == '__main__':
    main()
