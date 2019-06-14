import argparse
import os
import sys
import datetime
import rpm
import psycopg2
import mapper
import threading
import logging
import configparser

from psycopg2 import extras
from utils import cvt, packager_parse, get_logger, LockedIterator, get_conn_str, Timing, Display, valid_date, Cache
from manager import check_latest_version


@Timing.timeit('extract')
def check_package(conn, hdr):
    """Check whether the package is in the database.

    return sha1 hash of package from database or None
    """
    sql = "SELECT id FROM Package WHERE sha1header='{0}'"
    with conn.cursor() as cur:
        cur.execute(sql.format(cvt(hdr[rpm.RPMDBI_SHA1HEADER])))
        result = cur.fetchone()
        if result:
            return result[0]
        return None


@Timing.timeit('extract')
def insert_package(conn,  cache, hdr, **kwargs):
    """Insert information about package into database.

    Also:
    insert packager, files, requires, provides, confilcts, obsolets
    """
    map_package = mapper.get_package_map(hdr)
    map_package.update(**kwargs)
    # add packager
    name_email = packager_parse(cvt(hdr[rpm.RPMTAG_PACKAGER]))
    if name_email:
        pname, pemail = name_email
        pid = insert_smart(conn, 'Packager', name=pname, email=pemail)
        if pid:
            map_package.update(packager_id=pid)
    # add arch
    arch = mapper.detect_arch(hdr)
    if arch:
        aid = insert_smart(conn, 'Arch', name=arch)
        if aid:
            map_package.update(arch_id=aid)

    sql_insert = 'INSERT INTO {0} ({1}) VALUES ({2}) ON CONFLICT DO NOTHING RETURNING id'

    sql_insert_package = sql_insert.format(
        'Package',
        ', '.join(map_package.keys()),
        ', '.join(['%s'] * len(map_package))
    )

    package_id = None

    with conn.cursor() as cur:
        try:
            cur.execute(sql_insert_package, tuple(map_package.values()))
            package_id = cur.fetchone()
        except Exception as e:
            logging.getLogger('extract').error('{0} - {1}'.format(e, cur.query))

    if not package_id:
        return

    package_id = package_id[0]

    # insert package info
    map_package_info = mapper.get_package_info_map(hdr)
    map_package_info.update(package_id=package_id)
    sql_insert_package_info = sql_insert.format(
        'PackageInfo',
        ', '.join(map_package_info.keys()),
        ', '.join(['%s'] * len(map_package_info))
    )
    with conn.cursor() as cur:
        try:
            cur.execute(sql_insert_package_info, tuple(map_package_info.values()))
        except Exception as e:
            logging.getLogger('extract').error('{0} - {1}'.format(e, cur.query))

    insert_file(conn, cache, hdr, package_id)

    map_require = mapper.get_require_map(hdr)
    insert_list(conn, map_require, package_id, 'Require')

    map_conflict = mapper.get_conflict_map(hdr)
    insert_list(conn, map_conflict, package_id, 'Conflict')

    map_obsolete = mapper.get_obsolete_map(hdr)
    insert_list(conn, map_obsolete, package_id, 'Obsolete')

    map_provide = mapper.get_provide_map(hdr)
    insert_list(conn, map_provide, package_id, 'Provide')

    return package_id

@Timing.timeit('extract')
def insert_file(conn, cache, hdr, package_id,):
    map_file = mapper.get_file_map(hdr)
    map_file['fileusername_id'] = [cache['FileUserName'].get(i) for i in map_file['fileusername_id']]
    map_file['filegroupname_id'] = [cache['FileGroupName'].get(i) for i in map_file['filegroupname_id']]
    map_file['filelang_id'] = [cache['FileLang'].get(i) for i in map_file['filelang_id']]
    map_file['fileclass_id'] = [cache['FileClass'].get(i) for i in map_file['fileclass_id']]
    r = [(package_id,) + i for i in zip(*map_file.values())]
    with conn.cursor() as cur:
        for i in r:
            try:
                cur.callproc('insert_file', i)
            except Exception as e:
                logging.getLogger('extract').error('{0} - {1}'.format(e, cur.query))

@Timing.timeit('extract')
def insert_list(conn, tagmap, package_id, table_name):
    """Insert list as batch."""
    sql = 'INSERT INTO {0} (package_id, {1}) VALUES (%s, {2})'
    sql = sql.format(
        table_name,
        ', '.join(tagmap.keys()),
        ', '.join(['%s'] * len(tagmap))
    )
    r = [(package_id,) + i for i in zip(*tagmap.values())]
    with conn.cursor() as cur:
        try:
            extras.execute_batch(cur, sql, r)
        except Exception as e:
            logging.getLogger('extract').error('{0} - {1}'.format(e, cur.query))


@Timing.timeit('extract')
def insert_assigment_name(conn, assigment_name, assigment_tag=None, datetime_release=None):
    if datetime_release is None:
        datetime_release = datetime.datetime.now()
    with conn.cursor() as cur:
        sql = (
            'INSERT INTO AssigmentName (name, datetime_release, tag) '
            'VALUES (%s, %s, %s) RETURNING id'
        )
        cur.execute(sql, (assigment_name, datetime_release, assigment_tag))
        an_id = cur.fetchone()
        if an_id:
            return an_id[0]


@Timing.timeit('extract')
def insert_assigment(conn, assigmentname_id, package_id):
    sql = (
        'INSERT INTO Assigment (assigmentname_id, package_id)'
        ' VALUES (%s, %s) RETURNING id'
    )
    with conn.cursor() as cur:
        cur.execute(sql, (assigmentname_id, package_id))
        as_id = cur.fetchone()
        if as_id:
            return as_id[0]


@Timing.timeit('extract')
def insert_smart(conn, table, **fields):
    sql = (
        "INSERT INTO {table} ({key}) VALUES ({value}) ON CONFLICT ({key}) DO UPDATE set {conflicts} RETURNING id"
    )
    sql = sql.format(
        table=table,
        key=', '.join(fields.keys()),
        value=', '.join(['\'{0}\''.format(k) for k in fields.values()]),
        conflicts=', '.join(['{0}=EXCLUDED.{0}'.format(k) for k in fields.keys()]))
    result = None
    with conn.cursor() as cur:
        try:
            cur.execute(sql, fields)
            result = cur.fetchone()[0]
        except Exception as e:
            logging.getLogger('extract').error('{0} - {1}'.format(e, cur.query))
    return result


def insert_smart_wrap(conn, table):
    def wrap(key):
        return insert_smart(conn, table, value=key)
    return wrap


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
    def __init__(self, connection, cache, packages, aname_id, display, *args, **kwargs):
        self.connection = connection
        self.cache = cache
        self.packages = packages
        self.aname_id = aname_id
        self.display = display
        self.log = logging.getLogger('extract')
        super().__init__(*args, **kwargs)

    def run(self):
        ts = rpm.TransactionSet()
        self.log.debug('{0} start'.format(self.name))
        for package in self.packages:
            self.log.info('Processing: {0}'.format(package))
            try:
                header = get_header(ts, package)
                self.log.debug('Check: {0}'.format(package))
                pkg_id = check_package(self.connection, header)
                if pkg_id is None:
                    self.log.debug('Insert: {0}'.format(package))
                    pkg_id = insert_package(self.connection, self.cache, header, filename=os.path.basename(package))
                if pkg_id is None:
                    self.log.error('No id for {0}'.format(package))
                    raise RuntimeError('Unexpected behavior')
                self.log.debug('Add assigment: {0} id={1}'.format(package, pkg_id))
                insert_assigment(self.connection, self.aname_id, pkg_id)
            except psycopg2.DatabaseError as error:
                self.log.error(error)
            else:
                if self.display is not None:
                    self.display.inc()
        self.log.debug('{0} stop'.format(self.name))


def load(args):
    conn = psycopg2.connect(get_conn_str(args))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    if not check_latest_version(conn):
        conn.close()
        raise RuntimeError('Incorrect database schema version')
    if args.clean:
        clean_assigment(conn)
    cache = init_cache(conn, ['FileUserName', 'FileGroupName', 'FileLang', 'FileClass'])
    packages = LockedIterator(find_packages(args.path))
    aname_id = insert_assigment_name(conn, args.assigment, args.tag, args.date)
    if aname_id is None:
        raise RuntimeError('Unexpected behavior')
    workers = []
    connections = [conn]
    display = None
    if args.verbose:
        display = Display()
    for i in range(args.workers):
        conn = psycopg2.connect(get_conn_str(args))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        connections.append(conn)
        worker = Worker(conn, cache, packages, aname_id, display)
        worker.start()
        workers.append(worker)

    for w in workers:
        w.join()

    load_complete(conn, aname_id)

    for c in connections:
        if c is not None:
            c.close()

    if display is not None:
        display.conclusion()


def load_complete(conn, aid):
    sql = 'UPDATE AssigmentName SET complete=true WHERE id={0}'.format(aid)
    with conn.cursor() as cur:
        cur.execute(sql)


def clean_assigment(conn):
    with conn.cursor() as cur:
        # TODO:
        sql = 'SELECT id FROM AssigmentName WHERE complete=false'
        cur.execute(sql)
        ls = cur.fetchall()
        for i in ls:
            cur.execute('DELETE FROM Assigment WHERE assigmentname_id=%s', i)
            cur.execute('DELETE FROM AssigmentName WHERE id=%s', i)


def init_cache(conn, tables):
    cache = {}
    for tab in tables:
        cb = insert_smart_wrap(conn, tab)
        ch = Cache(cb)
        sql = 'SELECT value, id FROM {0}'.format(tab)
        with conn.cursor() as cur:
            cur.execute(sql)
            ch.load(cur)
        cache[tab] = ch
    return cache


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
    parser.add_argument('-C', '--clean', action='store_true', help='Delete uncompleted assigments')
    parser.add_argument('-A', '--date', type=valid_date, help='Set assigment datetime release. format YYYY-MM-DD')
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
