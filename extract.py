import argparse
import os
import datetime
import rpm
import psycopg2
import mapper
import threading
import logging
import configparser

from psycopg2 import extras
from utils import cvt, packager_parse, get_logger, LockedIterator, get_conn_str, Timing
from manager import check_latest_version


@Timing.timeit('extract')
def check_package(conn, hdr):
    """Check whether the package is in the database.

    return sha1 hash of package from database or None
    """
    sql = "SELECT sha1header FROM Package WHERE sha1header='{0}'"
    with conn.cursor() as cur:
        cur.execute(sql.format(cvt(hdr[rpm.RPMDBI_SHA1HEADER])))
        sha1header = cur.fetchone()
        if sha1header:
            return sha1header[0]
        return None


@Timing.timeit('extract')
def insert_package(conn, hdr, **kwargs):
    """Insert information about package into database.

    Also:
    insert packager, files, requires, provides, confilcts, obsolets
    """
    map_package = mapper.get_package_map(hdr)
    map_package.update(**kwargs)
    name_email = packager_parse(cvt(hdr[rpm.RPMTAG_PACKAGER]))
    if name_email is not None:
        pid = check_packager(conn, *name_email)
        if pid is None:
            pid = insert_packager(conn, *name_email)
        if pid is not None:
            map_package.update(packager_id=pid)

    sql_insert = (
            'INSERT INTO Package ({0}) VALUES ({1})'
            ' ON CONFLICT DO NOTHING RETURNING sha1header'
        ).format(
            ', '.join(map_package.keys()),
            ', '.join(['%s'] * len(map_package))
        )
    with conn.cursor() as cur:
        cur.execute(sql_insert, tuple(map_package.values()))
        package_sha1 = cur.fetchone()
        if package_sha1:
            package_sha1 = package_sha1[0]

            map_files = mapper.get_file_map(hdr)
            insert_list(cur, map_files, package_sha1, 'File')

            map_require = mapper.get_require_map(hdr)
            insert_list(cur, map_require, package_sha1, 'Require')

            map_conflict = mapper.get_conflict_map(hdr)
            insert_list(cur, map_conflict, package_sha1, 'Conflict')

            map_obsolete = mapper.get_obsolete_map(hdr)
            insert_list(cur, map_obsolete, package_sha1, 'Obsolete')

            map_provide = mapper.get_provide_map(hdr)
            insert_list(cur, map_provide, package_sha1, 'Provide')
    return package_sha1


@Timing.timeit('extract')
def insert_list(cursor, tagmap, package_sha1, table_name):
    """Insert list as batch."""
    sql = 'INSERT INTO {0} (package_sha1, {1}) VALUES (%s, {2})'
    sql = sql.format(
        table_name,
        ', '.join(tagmap.keys()),
        ', '.join(['%s'] * len(tagmap))
    )
    r = [(package_sha1,) + i for i in zip(*tagmap.values())]
    extras.execute_batch(cursor, sql, r)


@Timing.timeit('extract')
def insert_assigment_name(conn, assigment_name, assigment_tag=None):
    with conn.cursor() as cur:
        sql = (
            'INSERT INTO AssigmentName (name, datetime_release, tag) '
            'VALUES (%s, %s, %s) RETURNING id'
        )
        cur.execute(sql, (assigment_name, datetime.datetime.now(), assigment_tag))
        an_id = cur.fetchone()
        if an_id:
            conn.commit()
            return an_id[0]


@Timing.timeit('extract')
def check_assigment(conn, assigmentname_id, sha1header):
    """Check whether the assigment is in the database.

    return id or None
    """
    sql = (
        "SELECT id FROM Assigment WHERE assigmentname_id={0}"
        " AND package_sha1='{1}'"
    ).format(assigmentname_id, sha1header)
    with conn.cursor() as cur:
        cur.execute(sql)
        as_id = cur.fetchone()
        if as_id:
            return as_id[0]


@Timing.timeit('extract')
def insert_assigment(conn, assigmentname_id, sha1header):
    sql = (
        'INSERT INTO Assigment (assigmentname_id, package_sha1)'
        ' VALUES (%s, %s) RETURNING id'
    )
    with conn.cursor() as cur:
        cur.execute(sql, (assigmentname_id, sha1header))
        as_id = cur.fetchone()
        if as_id:
            return as_id[0]


@Timing.timeit('extract')
def check_packager(conn, name, email):
    """Check whether the packager is in the database.

    return id or None
    """
    sql = "SELECT id FROM Packager WHERE name='{0}' AND email='{1}'"
    with conn.cursor() as cur:
        cur.execute(sql.format(name, email))
        p_id = cur.fetchone()
        if p_id:
            return p_id[0]


@Timing.timeit('extract')
def insert_packager(conn, name, email):
    sql = 'INSERT INTO Packager (name, email) VALUES (%s, %s) RETURNING id'
    with conn.cursor() as cur:
        cur.execute(sql, (name, email))
        p_id = cur.fetchone()
        if p_id:
            conn.commit()
            return p_id[0]


def find_packages(path):
    """Recursively walk through directory for find rpm packages.

    return generator
    """
    for dirname, _, filenames in os.walk(path):
        for filename in filenames:
            f = os.path.join(dirname, filename)
            if f.endswith('.rpm') and not os.path.islink(f):
                yield f


def get_header(ts, rpmfile):
    return ts.hdrFromFdno(rpmfile)


class Worker(threading.Thread):
    def __init__(self, connection, packages, aname_id, *args, **kwargs):
        self.connection = connection
        self.packages = packages
        self.aname_id = aname_id
        self.log = logging.getLogger('extract')
        super().__init__(*args, **kwargs)

    def run(self):
        ts = rpm.TransactionSet()
        self.log.debug('{0} start'.format(self.name))
        for package in self.packages:
            self.log.info('Processing: {0}'.format(package))
            try:
                header = get_header(ts, package)
                sha1header = check_package(self.connection, header)
                if sha1header is None:
                    sha1header = insert_package(self.connection, header, filename=os.path.basename(package))
                if sha1header is None:
                    self.log.error('No sha1header for {0}'.format(package))
                    raise RuntimeError('Unexpected behavior')
                if check_assigment(self.connection, self.aname_id, sha1header) is None:
                    insert_assigment(self.connection, self.aname_id, sha1header)
            except psycopg2.DatabaseError as error:
                self.log.error(error)
            else:
                self.connection.commit()
        self.log.debug('{0} stop'.format(self.name))


def load(args):
    conn = psycopg2.connect(get_conn_str(args))
    if not check_latest_version(conn):
        conn.close()
        raise RuntimeError('Incorrect database schema version')
    packages = LockedIterator(find_packages(args.path))
    aname_id = insert_assigment_name(conn, args.assigment, args.tag)
    if aname_id is None:
        raise RuntimeError('Unexpected behavior')
    workers = []
    connections = [conn]
    for i in range(args.workers):
        conn = psycopg2.connect(get_conn_str(args))
        connections.append(conn)
        worker = Worker(conn, packages, aname_id)
        worker.start()
        workers.append(worker)

    for w in workers:
        w.join()

    for c in connections:
        if c is not None:
            c.close()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('assigment', type=str, help='Assigment name')
    parser.add_argument('path', type=str, help='Path to packages')
    parser.add_argument('-t', '--tag', type=str, help='Assigment tag')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database password')
    parser.add_argument('-u', '--user', type=str, help='Database login')
    parser.add_argument('-P', '--password', type=str, help='Database password')
    parser.add_argument('-w', '--workers', type=int, help='Workers count')
    parser.add_argument('-D', '--debug', action='store_true', help='Set logging level to debug')
    parser.add_argument('-T', '--timing', action='store_true', help='Enable timing for functions')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    return parser.parse_args()


def set_config(args):
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        # default
        args.workers = args.workers or cfg['DEFAULT'].get('workers', 10)
        # database
        if cfg.has_section('DATABASE'):
            section_db = cfg['DATABASE']
            args.dbname = args.dbname or section_db.get('dbname', None)
            args.host = args.host or section_db.get('host', None)
            args.port = args.port or section_db.get('port', None)
            args.user = args.user or section_db.get('user', None)
            args.password = args.password or section_db.get('password', None)
    return args


def main():
    args = get_args()
    args = set_config(args)
    log = get_logger('extract', args.assigment)
    if args.debug:
        log.setLevel(logging.DEBUG)
    if args.timing:
        Timing.timing = True
    log.info('Start loading packages')
    try:
        load(args)
    except Exception as error:
        log.error(error)
    finally:
        log.info('Stop loading packages')


if __name__ == '__main__':
    main()
