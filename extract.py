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
import fnmatch
import re
import iso as isopkg

from uuid import uuid4
from io import BufferedRandom, BytesIO
from utils import cvt, packager_parse, get_logger, LockedIterator, Timing, Display, valid_date, Cache, mmhash
from manager import check_latest_version


NAME = 'extract'

os.environ['LANG'] = 'C'

log = logging.getLogger(NAME)


@Timing.timeit(NAME)
def check_package(cache, hdr):
    """Check whether the package is in the database.

    return id of package from database or None
    """
    sha1 = cvt(hdr[rpm.RPMDBI_SHA1HEADER])
    pkghash = mmhash(sha1)
    log.debug('check package for sha1: {0}'.format(sha1))
    if pkghash in cache:
        return pkghash
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

    pkghash = map_package['pkghash']

    insert_file(conn, pkghash, hdr)

    map_require = mapper.get_require_map(hdr)
    insert_list(conn, map_require, pkghash, 'require')

    map_conflict = mapper.get_conflict_map(hdr)
    insert_list(conn, map_conflict, pkghash, 'conflict')

    map_obsolete = mapper.get_obsolete_map(hdr)
    insert_list(conn, map_obsolete, pkghash, 'obsolete')

    map_provide = mapper.get_provide_map(hdr)
    insert_list(conn, map_provide, pkghash, 'provide')

    conn.execute(sql_insert, [map_package])

    return pkghash


def unpack_map(tagmap):
    return [dict(zip(tagmap, v)) for v in zip(*tagmap.values())]


@Timing.timeit(NAME)
def insert_file(conn, pkghash, hdr):
    map_file = mapper.get_file_map(hdr)
    map_file['pkghash'] = itertools.cycle([pkghash])
    data = unpack_map(map_file)
    conn.execute(
        'INSERT INTO File_buffer ({0}) VALUES'.format(', '.join(map_file.keys())), 
        data
    )
    log.debug('insert file for pkghash: {0}'.format(pkghash))


@Timing.timeit('extract')
def insert_list(conn, tagmap, pkghash, dptype):
    """Insert list as batch."""
    tagmap['pkghash'] = itertools.cycle([pkghash])
    tagmap['dptype'] = itertools.cycle([dptype])
    data = unpack_map(tagmap)
    conn.execute(
        'INSERT INTO Depends_buffer ({0}) VALUES'.format(', '.join(tagmap.keys())),
        data
    )
    log.debug('insert list into: {0} for pkghash: {1}'.format(dptype, pkghash))


@Timing.timeit(NAME)
def insert_assignment_name(conn, assignment_name=None, uuid=None, tag=None, assignment_date=None, complete=0):
    if assignment_date is None:
        assignment_date = datetime.datetime.now()
    sql = 'INSERT INTO AssignmentName (uuid, assignment_name, assignment_date, tag, complete) VALUES'
    if uuid is None:
        uuid = str(uuid4())
    data = {
        'uuid': uuid,
        'assignment_name': assignment_name,
        'assignment_date': assignment_date,
        'tag': tag, 
        'complete': complete
    }
    conn.execute(sql, [data])
    log.debug('insert assignment name uuid: {0}'.format(uuid))
    # return data


@Timing.timeit(NAME)
def insert_assignment(conn, uuid, pkghash):
    conn.execute(
        'INSERT INTO Assignment_buffer (uuid, pkghash) VALUES',
        [dict(uuid=uuid, pkghash=p) for p in pkghash]
    )
    log.debug('insert assignment uuid: {0}, pkghash: {1}'.format(uuid, len(pkghash)))


def find_packages(args):
    """Recursively walk through directory for find rpm packages.

    return generator
    """
    path = args.path
    log.debug('scanning directory: {0}'.format(path))
    for dirname, _, filenames in os.walk(path):
        for filename in filenames:
            f = os.path.join(dirname, filename)
            if args.exclude is not None and fnmatch.fnmatch(f, args.exclude):
                log.debug('skip {}'.format(f))
                continue
            if f.endswith('.rpm') and not os.path.islink(f):
                yield f


def iso_find_packages(iso):
    for dirname, _, filenames in iso.walk(rr_path='/'):
        for filename in filenames:
            f = os.path.join(dirname, filename)
            if f.endswith('.rpm'):
                tmp_file = tempfile.TemporaryFile()
                iso.get_file_from_iso_fp(tmp_file, rr_path=f)
                tmp_file.seek(0)
                tmp_file.iname = f
                yield tmp_file


@Timing.timeit(NAME)
def get_header(ts, rpmfile):
    log.debug('read header {0}'.format(rpmfile))
    return ts.hdrFromFdno(rpmfile)


def check_iso(path):
    if os.path.isdir(path):
        return None
    iso = pycdlib.PyCdlib()
    fp = open(path, 'rb')
    try:
        iso.open_fp(fp)
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
    def __init__(self, connection, cache, packages, aname, display, repair, *args, **kwargs):
        self.connection = connection
        self.packages = packages
        self.aname = aname
        self.display = display
        self.cache = cache
        self.repair = repair
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
                pkghash = check_package(self.cache, header)
                kw = {'filename': os.path.basename(package)}
                if self.repair is not None:
                    if pkghash is not None:
                        repair_package(self.connection, header, self.repair, **kw)
                    continue
                if pkghash is None:
                    pkghash = insert_package(self.connection, header, **kw)
                    self.cache.add(pkghash)
                if pkghash is None:
                    raise RuntimeError('no id for {0}'.format(package))
                self.aname.add(pkghash)
            except Exception as error:
                log.error(error, exc_info=True)
            else:
                if self.display is not None:
                    self.display.inc()
        log.debug('thread stop')


def iso_get_info(iso, args):
    result = {}
    try:
        for dirname, _, filenames in iso.walk(rr_path='/.disk'):
            for filename in filenames:
                f = os.path.join(dirname, filename)
                data = BytesIO()
                iso.get_file_from_iso_fp(data, rr_path=f)
                result[filename.split('.')[0]] = data.getvalue().strip().decode('latin-1')
        result_string = '\n'.join(['{0}: {1}'.format(k, v) for k, v in result.items()])
        args.tag = result_string
    except Exception as error:
        log.error(error, exc_info=True)


def init_cache(conn):
    result = conn.execute('SELECT pkghash FROM Package_buffer')
    return {i[0] for i in result}


def check_assignment_name(conn, name):
    sql = 'SELECT COUNT(*) FROM AssignmentName WHERE assignment_name=%(aname)s'
    r = conn.execute(sql, {'aname': name})
    return r[0][0] > 0


def full_check(conn, hdr, map_package):
    # check files
    # rpm control sum
    map_file = mapper.get_file_map(hdr)
    fields = list(map_file.keys())  # save order
    data = unpack_map(map_file)
    csf_rpm = set([mmhash('.'.join([str(d[i]) for i in fields])) for d in data])  # calc hashsum for each row
    # db control sum
    res = conn.execute('SELECT {0} FROM File_buffer WHERE pkghash=%(pkghash)s'.format(', '.join(fields)), map_package)
    csf_db = set([mmhash('.'.join([str(i) for i in r])) for r in res])  # calc hashsum for each row
    ck_files = csf_rpm == csf_db
    if not ck_files:
        log.debug('package: {name} {pkgcs} files corrupted'.format(**map_package))
    # check depends
    fields = ['dpname', 'dpversion', 'flag']
    map_require = mapper.get_require_map(hdr)
    map_conflict = mapper.get_conflict_map(hdr)
    map_obsolete = mapper.get_obsolete_map(hdr)
    map_provide = mapper.get_provide_map(hdr)
    dep_data = unpack_map(map_require) + unpack_map(map_conflict) + unpack_map(map_obsolete) + unpack_map(map_provide)
    csd_rpm = set([mmhash('.'.join([str(d[i]) for i in fields])) for d in dep_data])
    res = conn.execute('SELECT {0} FROM Depends_buffer WHERE pkghash=%(pkghash)s'.format(', '.join(fields)), map_package)
    csd_db = set([mmhash('.'.join([str(i) for i in r])) for r in res])
    ck_depends = csd_rpm == csd_db
    if not ck_depends:
        log.debug('package: {name} {pkgcs} depends corrupted'.format(**map_package))
    return not (ck_files and ck_depends)


def repair_package(conn, hdr, repair, **kwargs):
    map_package = mapper.get_package_map(hdr)
    need_repair = False
    need_full_repair = False
    fields = list(map_package.keys())
    result = conn.execute(
        'SELECT {0} FROM Package_buffer WHERE pkghash=%(pkghash)s'.format(','.join(fields)),
        map_package
    )
    pkg = {k: v for k, v in zip(fields, result[0])}
    if map_package != pkg:
        need_repair = True
        log.debug('package: {name} {pkgcs} corrupted'.format(**map_package))
    if repair == 'repair' and need_repair:
        map_package.update(**kwargs)
        remove_package(conn, map_package)
        sql_insert = 'INSERT INTO Package_buffer ({0}) VALUES'.format(
            ', '.join(map_package.keys())
        )
        conn.execute(sql_insert, [map_package])
        return
    if repair in ['full-check', 'full-repair']:
        need_full_repair = full_check(conn, hdr, map_package)
    if repair == 'full-repair' and (need_repair or need_full_repair):
        remove_package(conn, map_package, full=True)
        insert_package(conn, hdr, **kwargs)


def remove_package(conn, mp, full=False):
    conn.execute('ALTER TABLE Package DELETE WHERE pkghash=%(pkghash)s', mp)
    if full:
        conn.execute('ALTER TABLE File DELETE WHERE pkghash=%(pkghash)s', mp)
        conn.execute('ALTER TABLE Depends DELETE WHERE pkghash=%(pkghash)s', mp)


def load(args):
    conn = get_client(args)
    # if not check_latest_version(conn):
    #     conn.disconnect()
    #     raise RuntimeError('Incorrect database schema version')
    # log.debug('check database version complete')
    iso = check_iso(args.path)
    if iso:
        if check_assignment_name(conn, args.assignment):
            raise NameError('This assignment name is already loaded!')
        packages = LockedIterator(iso_find_packages(iso))
        if args.date is None:
            r = os.stat(args.path)
            args.date = datetime.datetime.fromtimestamp(r.st_mtime)
        iso_get_info(iso, args)
    else:
        packages = LockedIterator(find_packages(args))
    workers = []
    connections = [conn]
    display = None
    if args.verbose and args.repair is None:
        display = Display(log)
    cache = init_cache(conn)
    aname = set()
    for i in range(args.workers):
        conn = get_client(args)
        connections.append(conn)
        worker = Worker(conn, cache, packages, aname, display, args.repair)
        worker.start()
        workers.append(worker)

    for w in workers:
        w.join()

    aname_id = str(uuid4())
    if args.repair is None:
        insert_assignment_name(
            conn,
            assignment_name=args.assignment,
            uuid=aname_id,
            tag=args.tag,
            assignment_date=args.date,
            complete=1
        )
        insert_assignment(conn, aname_id, aname)

    if iso:
        if args.constraint is not None:
            constraint_name = args.constraint,
        else:
            constraint_name = detect_assignment_name(conn, aname_id)
        if constraint_name:
            isopkg.process_iso(conn, iso, args, constraint_name)
        iso.close()

    for c in connections:
        if c is not None:
            c.disconnect()

    if display is not None:
        display.conclusion()


def detect_assignment_name(conn, uuid):
    sql = """SELECT assignment_name
FROM AssignmentName
         INNER JOIN
     (SELECT COUNT(pkghash) as countPkg, uuid
      FROM Assignment_buffer
      WHERE pkghash IN
            (SELECT pkghash FROM Assignment_buffer WHERE uuid = %(uuid)s)
      GROUP BY uuid) AS cpkg USING uuid
ORDER BY countPkg DESC
LIMIT 10
"""

    result = conn.execute(sql, {'uuid': uuid})
    return tuple({i[0] for i in result})


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('assignment', type=str, help='Assignment name')
    parser.add_argument('path', type=str, help='Path to packages')
    parser.add_argument('-t', '--tag', type=str, help='Assignment tag', default='')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database port')
    parser.add_argument('-u', '--user', type=str, help='Database login')
    parser.add_argument('-P', '--password', type=str, help='Database password')
    parser.add_argument('-w', '--workers', type=int, help='Workers count')
    parser.add_argument('-D', '--debug', action='store_true', help='Set logging level to debug')
    parser.add_argument('-T', '--timing', action='store_true', help='Enable timing for functions')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-A', '--date', type=valid_date, help='Set assignment datetime release. format YYYY-MM-DD')
    parser.add_argument('-E', '--exclude', type=str, help='Exclude filename from search')
    parser.add_argument('-C', '--constraint', type=str, help='Use constraint for searching')
    parser.add_argument('-R', '--repair', type=str, choices=['check', 'full-check', 'repair', 'full-repair'], 
                        help='check or restore database from rpm package')
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
    logger = get_logger(NAME, args.assignment, args.date)
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
