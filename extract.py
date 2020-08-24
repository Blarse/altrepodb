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


@Timing.timeit(NAME)
def insert_file(conn, pkghash, hdr):
    map_file = mapper.get_file_map(hdr)
    map_file['pkghash'] = itertools.cycle([pkghash])
    data = [dict(zip(map_file, v)) for v in zip(*map_file.values())]
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
    data = [dict(zip(tagmap, v)) for v in zip(*tagmap.values())]
    conn.execute(
        'INSERT INTO Depends_buffer ({0}) VALUES'.format(', '.join(tagmap.keys())),
        data
    )
    log.debug('insert list into: {0} for pkghash: {1}'.format(dptype, pkghash))


@Timing.timeit(NAME)
def insert_assigment_name(conn, assigment_name=None, uuid=None, tag=None, assigment_date=None, complete=0):
    if assigment_date is None:
        assigment_date = datetime.datetime.now()
    sql = 'INSERT INTO AssigmentName (uuid, assigment_name, assigment_date, tag, complete) VALUES'
    if uuid is None:
        uuid = str(uuid4())
    data = {
        'uuid': uuid,
        'assigment_name': assigment_name,
        'assigment_date': assigment_date,
        'tag': tag, 
        'complete': complete
    }
    conn.execute(sql, [data])
    log.debug('insert assigment name uuid: {0}'.format(uuid))
    # return data


@Timing.timeit(NAME)
def insert_assigment(conn, uuid, pkghash):
    conn.execute(
        'INSERT INTO Assigment_buffer (uuid, pkghash) VALUES',
        [dict(uuid=uuid, pkghash=p) for p in pkghash]
    )
    log.debug('insert assigment uuid: {0}, pkghash: {1}'.format(uuid, len(pkghash)))


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
    def __init__(self, connection, cache, packages, aname, display, _args, *args, **kwargs):
        self.connection = connection
        self.packages = packages
        self.aname = aname
        self.display = display
        self.cache = cache
        self.repair = _args.repair
        self.dry_repair = _args.dry_repair
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
                if pkghash is None:
                    pkghash = insert_package(self.connection, header, filename=os.path.basename(package))
                    self.cache.add(pkghash)
                elif self.repair or self.dry_repair:
                    repair_package(self.connection, header, self.dry_repair)
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


def check_assigment_name(conn, name):
    sql = 'SELECT COUNT(*) FROM AssigmentName WHERE assigment_name=%(aname)s'
    r = conn.execute(sql, {'aname': name})
    return r[0][0] > 0


def repair_package(conn, hdr, dry):
    map_package = mapper.get_package_map(hdr)
    sql = 'SELECT summary, description FROM Package WHERE pkghash=%(pkghash)s'
    result = conn.execute(sql, map_package)
    if result[0][0] != map_package['summary'] or result[0][1] != map_package['description']:
        if not dry:
            conn.execute(
                ('ALTER TABLE Package UPDATE summary=%(summary)s,'
                ' description=%(description)s WHERE pkghash=%(pkghash)s'), map_package)
        log.debug('package: {0} {1} corrupted'.format(map_package['name'], map_package['pkghash']))


def load(args):
    conn = get_client(args)
    # if not check_latest_version(conn):
    #     conn.disconnect()
    #     raise RuntimeError('Incorrect database schema version')
    # log.debug('check database version complete')
    iso = check_iso(args.path)
    if iso:
        if check_assigment_name(conn, args.assigment):
            raise NameError('This assigment name is already loaded!')
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
    if args.verbose:
        display = Display(log)
    cache = init_cache(conn)
    aname = set()
    for i in range(args.workers):
        conn = get_client(args)
        connections.append(conn)
        worker = Worker(conn, cache, packages, aname, display, args)
        worker.start()
        workers.append(worker)

    for w in workers:
        w.join()

    aname_id = str(uuid4())
    insert_assigment_name(
        conn,
        assigment_name=args.assigment,
        uuid=aname_id,
        tag=args.tag,
        assigment_date=args.date,
        complete=1
    )
    insert_assigment(conn, aname_id, aname)

    if iso:
        if args.constraint is not None:
            constraint_name = args.constraint,
        else:
            constraint_name = detect_assigment_name(conn, aname_id)
        if constraint_name:
            isopkg.process_iso(conn, iso, args, constraint_name)
        iso.close()

    for c in connections:
        if c is not None:
            c.disconnect()

    if display is not None:
        display.conclusion()


def detect_assigment_name(conn, uuid):
    sql = """SELECT assigment_name
FROM AssigmentName
         INNER JOIN
     (SELECT COUNT(pkghash) as countPkg, uuid
      FROM Assigment_buffer
      WHERE pkghash IN
            (SELECT pkghash FROM Assigment_buffer WHERE uuid = %(uuid)s)
      GROUP BY uuid) AS cpkg USING uuid
ORDER BY countPkg DESC
LIMIT 10
"""

    result = conn.execute(sql, {'uuid': uuid})
    return tuple({i[0] for i in result})


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('assigment', type=str, help='Assigment name')
    parser.add_argument('path', type=str, help='Path to packages')
    parser.add_argument('-t', '--tag', type=str, help='Assigment tag', default='')
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
    parser.add_argument('-A', '--date', type=valid_date, help='Set assigment datetime release. format YYYY-MM-DD')
    parser.add_argument('-E', '--exclude', type=str, help='Exclude filename from search')
    parser.add_argument('-C', '--constraint', type=str, help='Use constraint for searching')
    parser.add_argument('-R', '--repair', action='store_true', help='Update existing fields in database from rpm package')
    parser.add_argument('-r', '--dry-repair', action='store_true', help='Show corrupted package')
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
