import argparse
import os
import sys
import datetime
import rpm
import clickhouse_driver as chd
import mapper
import threading
import logging
import configparser
import tempfile
import pycdlib
import itertools

from uuid import uuid4
from io import BufferedRandom
from utils import cvt, packager_parse, get_logger, LockedIterator, Timing, Display, valid_date, Cache
from manager import check_latest_version


NAME = 'extract'


log = logging.getLogger(NAME)


@Timing.timeit(NAME)
def check_package(cache, hdr):
    """Check whether the package is in the database.

    return id of package from database or None
    """
    sha1 = cvt(hdr[rpm.RPMDBI_SHA1HEADER])
    log.debug('check package for sha1: {0}'.format(sha1))
    if sha1 in cache:
        return sha1
    return None


@Timing.timeit(NAME)
def insert_package(conn, hdr, **kwargs):
    """Insert information about package into database.

    Also:
    insert packager, files, requires, provides, confilcts, obsolets
    """
    map_package = mapper.get_package_map(hdr)
    map_package.update(**kwargs)

    sql_insert = 'INSERT INTO Package_buffer ({0}) VALUES'.format(
        ', '.join(map_package.keys())
    )

    pkgcs = map_package['pkgcs']

    insert_file(conn, pkgcs, hdr)

    map_require = mapper.get_require_map(hdr)
    insert_list(conn, map_require, pkgcs, 'require')

    map_conflict = mapper.get_conflict_map(hdr)
    insert_list(conn, map_conflict, pkgcs, 'conflict')

    map_obsolete = mapper.get_obsolete_map(hdr)
    insert_list(conn, map_obsolete, pkgcs, 'obsolete')

    map_provide = mapper.get_provide_map(hdr)
    insert_list(conn, map_provide, pkgcs, 'provide')

    conn.execute(sql_insert, [map_package])

    return pkgcs


@Timing.timeit(NAME)
def insert_file(conn, pkgcs, hdr):
    map_file = mapper.get_file_map(hdr)
    map_file['pkgcs'] = itertools.cycle([pkgcs])
    data = [dict(zip(map_file, v)) for v in zip(*map_file.values())]
    conn.execute(
        'INSERT INTO File_buffer ({0}) VALUES'.format(', '.join(map_file.keys())), 
        data
    )
    log.debug('insert file for pkgcs: {0}'.format(pkgcs))


@Timing.timeit('extract')
def insert_list(conn, tagmap, pkgcs, dptype):
    """Insert list as batch."""
    tagmap['pkgcs'] = itertools.cycle([pkgcs])
    tagmap['dptype'] = itertools.cycle([dptype])
    data = [dict(zip(tagmap, v)) for v in zip(*tagmap.values())]
    conn.execute(
        'INSERT INTO Depends_buffer ({0}) VALUES'.format(', '.join(tagmap.keys())),
        data
    )
    log.debug('insert list into: {0} for pkgcs: {1}'.format(dptype, pkgcs))


@Timing.timeit(NAME)
def insert_assigment_name(conn, name=None, uuid=None, tag=None, datetime_release=None, complete=0):
    if datetime_release is None:
        datetime_release = datetime.datetime.now()
    sql = 'INSERT INTO AssigmentName (id, name, datetime_release, tag, complete) VALUES'
    if uuid is None:
        uuid = str(uuid4())
    data = {
        'id': uuid,
        'name': name,
        'datetime_release': datetime_release,
        'tag': tag, 
        'complete': complete
    }
    conn.execute(sql, [data])
    log.debug('insert assigment name id: {0}'.format(uuid))
    # return data


@Timing.timeit(NAME)
def insert_assigment(conn, uuid, pkgcs):
    conn.execute(
        'INSERT INTO Assigment_buffer (uuid, pkgcs) VALUES',
        [dict(uuid=uuid, pkgcs=p) for p in pkgcs]
    )
    log.debug('insert assigment uuid: {0}, pkgcs: {1}'.format(uuid, len(pkgcs)))


def find_packages(path):
    """Recursively walk through directory for find rpm packages.

    return generator
    """
    log.debug('scanning directory: {0}'.format(path))
    for dirname, _, filenames in os.walk(path):
        for filename in filenames:
            f = os.path.join(dirname, filename)
            if f.endswith('.rpm') and not os.path.islink(f):
                yield f


def iso_find_packages(iso):
    for dirname, _, filenames in iso.walk(iso_path='/'):
        for filename in filenames:
            f = os.path.join(dirname, filename)
            if f.endswith('.RPM;1'):
                tmp_file = tempfile.TemporaryFile()
                iso.get_file_from_iso_fp(tmp_file, iso_path=f)
                tmp_file.seek(0)
                tmp_file.iname = f.lower()[:-2]
                yield tmp_file


@Timing.timeit(NAME)
def get_header(ts, rpmfile):
    log.debug('read header {0}'.format(rpmfile))
    return ts.hdrFromFdno(rpmfile)


def check_iso(path):
    if os.path.isdir(path):
        return None
    iso = pycdlib.PyCdlib()
    try:
        iso.open(path)
    except pycdlib.pycdlibexception.PyCdlibInvalidInput:
        log.error('error open iso: {0}'.format(path))
        return None
    return iso


def get_client(args):
    return chd.Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password
    )


class Worker(threading.Thread):
    def __init__(self, connection, cache, packages, aname, display, *args, **kwargs):
        self.connection = connection
        self.packages = packages
        self.aname = aname
        self.display = display
        self.cache = cache
        super().__init__(*args, **kwargs)

    def run(self):
        ts = rpm.TransactionSet()
        log.debug('thread start')
        for package in self.packages:
            try:
                header = get_header(ts, package)
                if isinstance(package, BufferedRandom):
                    package.close()
                    package = package.iname
                log.debug('process: {0}'.format(package))
                pkgcs = check_package(self.cache, header)
                if pkgcs is None:
                    pkgcs = insert_package(self.connection, header, filename=os.path.basename(package))
                    self.cache.add(pkgcs)
                if pkgcs is None:
                    raise RuntimeError('no id for {0}'.format(package))
                self.aname.add(pkgcs)
            except Exception as error:
                log.error(error, exc_info=True)
            else:
                if self.display is not None:
                    self.display.inc()
        log.debug('thread stop')


def init_cache(conn):
    result = conn.execute('SELECT pkgcs FROM Package_buffer')
    return {i[0] for i in result}


def load(args):
    conn = get_client(args)
    if not check_latest_version(conn):
        conn.disconnect()
        raise RuntimeError('Incorrect database schema version')
    log.debug('check database version complete')
    iso = check_iso(args.path)
    if iso:
        packages = LockedIterator(iso_find_packages(iso))
    else:
        packages = LockedIterator(find_packages(args.path))
    workers = []
    connections = [conn]
    display = None
    if args.verbose:
        display = Display(log)
    cache = init_cache(conn)
    aname = set()
    for i in range(args.workers):
        conn = get_client(args)
        connections.append(conn)
        worker = Worker(conn, cache, packages, aname, display)
        worker.start()
        workers.append(worker)

    for w in workers:
        w.join()

    aname_id = str(uuid4())
    insert_assigment_name(
        conn,
        name=args.assigment,
        uuid=aname_id,
        tag=args.tag,
        datetime_release=args.date,
        complete=1
    )
    insert_assigment(conn, aname_id, aname)

    if iso:
        iso.close()

    for c in connections:
        if c is not None:
            c.disconnect()

    if display is not None:
        display.conclusion()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('assigment', type=str, help='Assigment name')
    parser.add_argument('path', type=str, help='Path to packages')
    parser.add_argument('-t', '--tag', type=str, help='Assigment tag', default='')
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
    parser.add_argument('-A', '--date', type=valid_date, help='Set assigment datetime release. format YYYY-MM-DD')
    return parser.parse_args()


def set_config(args):
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        # default
        args.workers = args.workers or cfg['DEFAULT'].getint('workers', 10)
        # database
        if cfg.has_section('DATABASE'):
            section_db = cfg['DATABASE']
            args.dbname = args.dbname or section_db.get('dbname', 'default')
            args.host = args.host or section_db.get('host', 'localhost')
            args.port = args.port or section_db.get('port', None)
            args.user = args.user or section_db.get('user', 'default')
            args.password = args.password or section_db.get('password', '')
    else:
        args.workers = args.workers or 10
        args.dbname = args.dbname or 'default'
        args.host = args.host or 'localhost'
        args.port = args.port or None
        args.user = args.user or 'default'
        args.password = args.password or ''
    return args


def main():
    args = get_args()
    args = set_config(args)
    logger = get_logger(NAME, args.assigment, args.date)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.timing:
        Timing.timing = True
    logger.info('start loading packages')
    try:
        load(args)
    except Exception as error:
        logger.error(error, exc_info=True)
    finally:
        logger.info('stop loading packages')


if __name__ == '__main__':
    main()
