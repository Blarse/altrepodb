import argparse
import os
import sys
import datetime
import time
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
from utils import cvt, get_logger, LockedIterator, Timing, Display, valid_date, \
    mmhash, md5_from_file, sha256_from_file, join_dicts_with_as_string, FunctionalNotImplemented
from manager import check_latest_version
from collections import defaultdict
from pathlib import Path
import shutil
import lzma


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


def get_partial_pkg_map(hdr, key_list):
    map_package = mapper.get_package_map(hdr)
    res = {}
    for key in key_list:
        res[key] = map_package[key]
    return res


@Timing.timeit(NAME)
def insert_package(conn, hdr, **kwargs):
    """Insert information about package into database.

    Also:
    insert packager, files, requires, provides, confilcts, obsolets
    """
    map_package = mapper.get_package_map(hdr)
    map_package.update(**kwargs)

    # TODO: PLAYING AROUND WITH CHANGELOGS
    chlog = map_package['pkg_changelog']
    del map_package['pkg_changelog']
    map_package['pkg_changelog.date'] = []
    map_package['pkg_changelog.name'] = []
    map_package['pkg_changelog.evr'] = []
    map_package['pkg_changelog.hash'] = []
    payload = []
    for k, v in chlog.items():
        map_package['pkg_changelog.date'].append(v[0])
        map_package['pkg_changelog.name'].append(v[1])
        map_package['pkg_changelog.evr'].append(v[2])
        map_package['pkg_changelog.hash'].append(k)
        payload.append({
            'chlog_hash': k,
            'chlog_text': v[3]
        })
    conn.execute("""INSERT INTO Changelog_buffer (*) VALUES""", payload)

    sql_insert = 'INSERT INTO Packages_buffer ({0}) VALUES'.format(
        ', '.join(map_package.keys())
    )

    pkghash = map_package['pkg_hash']

    insert_file(conn, pkghash, hdr)

    map_require = mapper.get_require_map(hdr)
    insert_list(conn, map_require, pkghash, 'require')

    map_conflict = mapper.get_conflict_map(hdr)
    insert_list(conn, map_conflict, pkghash, 'conflict')

    map_obsolete = mapper.get_obsolete_map(hdr)
    insert_list(conn, map_obsolete, pkghash, 'obsolete')

    map_provide = mapper.get_provide_map(hdr)
    insert_list(conn, map_provide, pkghash, 'provide')

    conn.execute(sql_insert, [map_package], settings={'types_check': True})

    return pkghash


def unpack_map(tagmap):
    return [dict(zip(tagmap, v)) for v in zip(*tagmap.values())]


@Timing.timeit(NAME)
def insert_file(conn, pkghash, hdr):
    map_file = mapper.get_file_map(hdr)
    map_file['pkg_hash'] = itertools.cycle([pkghash])
    data = unpack_map(map_file)
    conn.execute(
        'INSERT INTO Files_buffer ({0}) VALUES'.format(', '.join(map_file.keys())),
        data
    )
    log.debug('insert file for pkghash: {0}'.format(pkghash))


@Timing.timeit('extract')
def insert_list(conn, tagmap, pkghash, dptype):
    """Insert list as batch."""
    tagmap['pkg_hash'] = itertools.cycle([pkghash])
    tagmap['dp_type'] = itertools.cycle([dptype])
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
def insert_pkgset_name(conn, name, uuid, puuid, ruuid, depth, tag, date, complete, kv_args):
    if date is None:
        date = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    sql = 'INSERT INTO PackageSetName (*) VALUES'
    # if uuid is None:
    #     uuid = str(uuid4())
    data = {
        'pkgset_uuid': uuid,
        'pkgset_puuid': puuid,
        'pkgset_ruuid': ruuid,
        'pkgset_depth': depth,
        'pkgset_name': name,
        'pkgset_date': date,
        'pkgset_tag': tag, 
        'pkgset_complete': complete,
        'pkgset_kv.k': [k for k, v in kv_args.items() if v is not None],
        'pkgset_kv.v': [v for k, v in kv_args.items() if v is not None],
    }
    conn.execute(sql, [data], settings={'types_check': True})
    log.debug('insert assignment name uuid: {0}'.format(uuid))


@Timing.timeit(NAME)
def insert_pkgset(conn, uuid, pkghash):
    conn.execute(
        'INSERT INTO PackageSet_buffer (pkgset_uuid, pkg_hash) VALUES',
        [dict(pkgset_uuid=uuid, pkg_hash=p) for p in pkghash]
    )
    log.debug('insert packageset uuid: {0}, pkg_hash: {1}'.format(uuid, len(pkghash)))


@Timing.timeit(NAME)
def insert_pkg_hashes(conn, pkg_hashes):
    payload = []
    for k, v in pkg_hashes:
        payload.append({
            'pkgh_mmh': pkg_hashes[k]['mmh'],
            'pkgh_md5': pkg_hashes[k]['md5'],
            'pkgh_sha1': pkg_hashes[k]['sha1'],
            'pkgh_sha256': pkg_hashes[k]['sha256']
        })
    settings = {'strings_as_bytes': True}
    conn.execute("INSERT INTO PackageHash_buffer (*) VALUES",
                 payload,
                 settings=settings)


@Timing.timeit(NAME)
def insert_pkg_hash_single(conn, pkg_hash):
    settings = {'strings_as_bytes': True}
    conn.execute("INSERT INTO PackageHash_buffer (*) VALUES",
                 [{
                    'pkgh_mmh': pkg_hash['mmh'],
                    'pkgh_md5': pkg_hash['md5'],
                    'pkgh_sha1': pkg_hash['sha1'],
                    'pkgh_sha256': pkg_hash['sha256']
                 }],
                 settings=settings)


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
    def __init__(self, connection, pkg_cache, src_repo_cache, pkg_repo_cache, packages, aname, display, repair, is_src=False, *args, **kwargs):
        self.connection = connection
        self.packages = packages
        self.aname = aname
        self.display = display
        self.src_repo_cache = src_repo_cache
        self.pkg_repo_cache = pkg_repo_cache
        self.cache = pkg_cache
        self.repair = repair
        self.is_src = is_src
        super().__init__(*args, **kwargs)

    def run(self):
        ts = rpm.TransactionSet()
        log.debug('thread start')
        count = 0
        for package in self.packages:
            try:
                count += 1
                header = get_header(ts, package)
                map_package = get_partial_pkg_map(header, (
                    'pkg_sourcepackage',
                    'pkg_sourcerpm',
                    'pkg_hash',
                    'pkg_arch',
                    'pkg_cs'
                    ))
                kw = {'pkg_filename': Path(package).name}
                
                if self.is_src:
                    #  store pkg mmh and sha1
                    self.src_repo_cache[kw['pkg_filename']]['mmh'] = map_package['pkg_hash']
                    self.src_repo_cache[kw['pkg_filename']]['sha1'] = map_package['pkg_cs']
                    # set source rpm name and hash to self
                    kw['pkg_sourcerpm'] = kw['pkg_filename']
                    kw['pkg_srcrpm_hash'] = map_package['pkg_hash']
                else:
                    #  store pkg mmh and sha1
                    self.pkg_repo_cache[kw['pkg_filename']]['mmh'] = map_package['pkg_hash']
                    self.pkg_repo_cache[kw['pkg_filename']]['sha1'] = map_package['pkg_cs']
                    # set source rpm name and hash
                    kw['pkg_srcrpm_hash'] = self.src_repo_cache[map_package['pkg_sourcerpm']]['mmh']

                # check if 'pkg_srcrpm_hash' is None - it's Ok for 'x86_64-i586'
                if map_package['pkg_arch'] == 'x86_64-i586' and kw['pkg_srcrpm_hash'] is None:
                    kw['pkg_srcrpm_hash'] = 0
                
                if isinstance(package, BufferedRandom):
                    package.close()
                    package = package.iname
                log.debug('process: {0}'.format(package))
                pkghash = check_package(self.cache, header)
                # kw = {'filename': Path(package).name}
                if self.repair is not None:
                    if pkghash is not None:
                        repair_package(self.connection, header, self.repair, **kw)
                    continue
                if pkghash is None:
                    # pkghash = map_package['pkg_hash']
                    pkghash = insert_package(self.connection, header, **kw)
                    self.cache.add(pkghash)
                    # insert package hashes to PackageHash_buffer
                    if self.is_src:
                        insert_pkg_hash_single(self.connection, self.src_repo_cache[kw['pkg_filename']])
                    else:
                        insert_pkg_hash_single(self.connection, self.pkg_repo_cache[kw['pkg_filename']])
                if pkghash is None:
                    raise RuntimeError('no id for {0}'.format(package))
                self.aname.add(pkghash)
            except Exception as error:
                log.error(error, exc_info=True)
            else:
                if self.display is not None:
                    self.display.inc()
        log.debug('thread stop')


def worker_pool(pkg_cache, src_repo_cache, pkg_repo_cache, packages_list, pkgset, display, is_src, args):
    workers = []
    connections = []

    packages = LockedIterator((pkg for pkg in packages_list))

    for i in range(args.workers):
        conn = get_client(args)
        connections.append(conn)
        worker = Worker(conn, pkg_cache, src_repo_cache, pkg_repo_cache, packages, pkgset, display, args.repair, is_src)
        worker.start()
        workers.append(worker)

    for w in workers:
        w.join()

    for c in connections:
        if c is not None:
            c.disconnect()


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
    result = conn.execute('SELECT pkgh_mmh FROM PackageHash_buffer')
    return {i[0] for i in result}


@Timing.timeit('PkgHashTmp')
def init_hash_temp_table(conn, hashes):
    payload = []
    result = conn.execute(
        """CREATE TEMPORARY TABLE IF NOT EXISTS PkgHashTmp
        (
            name    String,
            md5     FixedString(16),
            sha256  FixedString(32)
        )"""
    )
    for k, v in hashes.items():
        payload.append(
            {
                'name':     k,
                'md5':      hashes[k]['md5'],
                'sha256':   hashes[k]['sha256']
            }
        )
    result = conn.execute("INSERT INTO PkgHashTmp (*) VALUES", payload)
    log.debug(f"Inserted {len(payload)} hashes into PkgHashTmp")
    # Free memory immediatelly
    del payload
    # return {i[0] for i in result}


@Timing.timeit('PkgHash_check_md5')
def get_packages_not_in_db_by_md5(conn):
    result = conn.execute(
        """SELECT md5 FROM PkgHashTmp 
        WHERE md5 NOT IN (
            SELECT pkgh_md5 FROM PackageHash_buffer
        )""",
        settings={'strings_as_bytes': True}
    )
    log.debug(f"Found {len(result)} packages are not in PackageHash")
    return {i[0] for i in result}


@Timing.timeit('PkgHash_check_sha256')
def get_packages_not_in_db_by_sha256(conn):
    result = conn.execute(
        """SELECT md5 FROM PkgHashTmp 
        WHERE sha256 NOT IN (
            SELECT pkgh_sha256 FROM PackageHash_buffer
        )""",
        settings={'strings_as_bytes': True}
    )
    log.debug(f"Found {len(result)} packages are not in PackageHashes")
    return {i[0] for i in result}


@Timing.timeit('PkgHash_check_md5_not_in_db')
def update_hases_from_db(conn, repo_cache):
    # select all repo packages that already in DB by md5
    result = conn.execute(
        """SELECT t1.name, t1.md5, t2.mmh, t2.sha1 
        FROM (SELECT name, md5 FROM PkgHashTmp WHERE md5 IN 
                (SELECT pkgh_md5 FROM PackageHash_buffer)) AS t1 
        LEFT JOIN 
            (SELECT pkgh_md5 AS md5, pkgh_mmh AS mmh, pkgh_sha1 AS sha1 FROM PackageHash_buffer) AS t2
        ON t1.md5 = t2.md5""",
        settings={'strings_as_bytes': True}
    )
    log.debug(f"Found {len(result)} packages are in PackageHash")
    if len(result):
        for (k, *v) in result:
            if len(v) == 3:
                if k in repo_cache.keys():
                    # DEBUG
                    if not isinstance(v[1], int) or not isinstance(v[2], bytes):
                        log.critical(f"Value error for {v} in {result}")
                        raise ValueError("Wrong values from PackageHash")
                    # DEBUG
                    # repo_cache[k]['md5'] = v[0]
                    repo_cache[k]['mmh'] = v[1]
                    repo_cache[k]['sha1'] = v[2]


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


def unxz(fname, mode='b'):
    """Reads '.xz' compressed file contents

    Args:
        fname (path-like or string): path to comressed file
        mode (str, optional): file read mode: binary or text. Defaults to 'b'.

    Returns:
        (bytes or text): contents of comressed '.xz' file
    """
    if mode == 'b':
        with lzma.open(fname, 'rb') as f:
            res = f.read()
        return res
    else:
        with lzma.open(fname, 'rt') as f:
            res = f.read()
        return res


def read_release_components(f):
    """Read components from 'release' file in reposiory tree

    Args:
        f (path-like object): path to 'release' file

    Returns:
        list(string): list of components
    """
    with f.open(mode='r') as fd:
        for line in fd.readlines():
            ls = line.split(':')
            if ls[0] == 'Components':
                return [x.strip() for x in ls[1].split()]


def read_headers_from_xz_pkglist(fname):
    """Read headers from apt hash file

    Args:
        fname (path-like object): path to 'pkglist.xz' file

    Returns:
        list(rpm header): list of RPM headers objects
    """
    # uncompress and read headers from list
    r, w = os.pipe()
    r, w = os.fdopen(r, 'rb', 0), os.fdopen(w, 'wb', 0)
    pid = os.fork()
    if pid:  # Parser
        w.close()
        log.debug(f"Parsing headers from {fname}")
        hdrs = rpm.readHeaderListFromFD(r)
        return hdrs
    else:  # Decompressor
        r.close()
        fdno = lzma.open(fname, 'rb')
        log.debug(f"[DEBUG] Decompressing {fname}")
        shutil.copyfileobj(fdno, w)
        os._exit(0)


def check_repo_date_name_in_db(conn, pkgset_name, pkgset_date):
    result = conn.execute(
        f"SELECT COUNT(*) FROM PackageSetName WHERE pkgset_name='{pkgset_name}' AND pkgset_date='{pkgset_date}'"
    )
    return result[0][0] != 0


def read_repo_structure(repo_name, repo_path):
    """Reads repository structure for given path and store

    Args:
        repo_name (string): name of processed repository
        repo_path (string): path to repository root

    Returns:
        dict: repository structure and file's hashes
    """
    ARCHS = ('src', 'aarch64', 'armh', 'i586', 'ppc64le', 'x86_64', 'x86_64-i586', 'noarch', 'mipsel', 'e2k', 'e2kv4')
    repo = {
        'repo': {
            'name': repo_name,
            'uuid': str(uuid4()),
            'puuid': '00000000-0000-0000-0000-000000000000',
            'path': str(Path(repo_path)),
            'kwargs': defaultdict(lambda: None, key=None)
        },
        'src': {
            'name': 'srpm',
            'uuid': str(uuid4()),
            'puuid': None,
            'path': []
        },
        'arch': {
            'archs': [],
            'kwargs': defaultdict(lambda: None, key=None)
        },
        'comp': {
            'comps': [],
            'kwargs': defaultdict(lambda: None, key=None)
        },
        'src_hashes': defaultdict(lambda: defaultdict(lambda: None, key=None)),
        'pkg_hashes': defaultdict(lambda: defaultdict(lambda: None, key=None))
    }

    repo['src']['puuid'] = repo['repo']['uuid']
    repo['arch']['kwargs']['all_archs'] = set()
    repo['comp']['kwargs']['all_comps'] = set()

    root = Path(repo['repo']['path'])

    if not Path.joinpath(root, 'files/list').is_dir() or \
            not [_ for _ in root.iterdir() if (_.is_dir() and _.name in ARCHS)]:
        # TODO: add support for ISO-like repositories
        msg = f"The path '{str(root)}' is not regular repo structure root"
        raise FunctionalNotImplemented(msg)

    for arch_dir in [_ for _ in root.iterdir() if (_.is_dir() and _.name in ARCHS)]:
        # if arch_dir.is_dir() and arch_dir.name in ARCHS:
        repo['arch']['archs'].append({'name': arch_dir.name,
                                      'uuid': str(uuid4()),
                                      'puuid': repo['repo']['uuid'],
                                      'path': arch_dir.name})
        repo['arch']['kwargs']['all_archs'].add(arch_dir.name)
        # append '%ARCH%/SRPM.classic' path to 'src'
        repo['src']['path'].append('/'.join(arch_dir.joinpath('SRPMS.classic').parts[-2:]))
        # check '%ARCH%/base' directory for components
        base_subdir = arch_dir.joinpath('base')
        if base_subdir.is_dir():
            # store components and paths to it
            for comp_name in read_release_components(base_subdir.joinpath('release')):
                repo['comp']['comps'].append({'name': comp_name,
                                              'uuid': str(uuid4()),
                                              'puuid': repo['arch']['archs'][-1]['uuid'],
                                              'path': '/'.join(arch_dir.joinpath('RPMS.' + comp_name).parts[-2:])})
                repo['comp']['kwargs']['all_comps'].add(comp_name)
            # load MD5 from '%ARCH%/base/[pkg|src]list.%COMP%.xz'
            pkglist_names = ['srclist.classic']
            pkglist_names += [('pkglist.' + _) for _ in repo['comp']['kwargs']['all_comps']]
            for pkglist_name in pkglist_names:
                f = base_subdir.joinpath(pkglist_name + '.xz')
                if f.is_file():
                        hdrs = read_headers_from_xz_pkglist(f)
                        for hdr in hdrs:
                            pkg_name = cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYFILENAME])
                            pkg_md5 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYMD5]))
                            if pkglist_name.startswith('srclist'):
                                repo['src_hashes'][pkg_name]['md5'] = pkg_md5
                            else:
                                repo['pkg_hashes'][pkg_name]['md5'] = pkg_md5

    # check if '%root%/files/list' exists and load all data from it
    p = root.joinpath('files/list')
    if p.is_dir():
        # load task info
        f = Path.joinpath(p, 'task.info')
        if f.is_file():
            contents = (_ for _ in f.read_text().split('\n') if len(_))
            for c in contents:
                k, v = c.split()
                repo['repo']['kwargs'][k] = v

        # load all SHA256 hashes
        for arch in ARCHS:
            f = p.joinpath(arch + '.hash.xz')
            if f.is_file():
                contents = (_ for _ in unxz(f, 't').split('\n') if len(_))
                if arch == 'src':
                    # load to src_hashes
                    for c in contents:
                        pkg_name = c.split()[1]
                        pkg_sha256 = bytes.fromhex(c.split()[0])
                        # calculate and store missing MD5 hashes for 'src.rpm'
                        # TODO: workaround for missing/unhandled src.gostcrypto.xz
                        if pkg_name not in repo['src_hashes']:
                            log.info(f"{pkg_name}'s MD5 not found. Calculating it from file")
                            # calculate missing MD5 from file here
                            f = root.joinpath('files', 'SRPMS', pkg_name)
                            if f.is_file():
                                pkg_md5 = bytes.fromhex(md5_from_file(f))
                                repo['src_hashes'][pkg_name]['md5'] = pkg_md5
                            else:
                                log.error(f"Cant find file to calculate MD5 for {pkg_name} from {root.joinpath('files, ''SRPMS')}")
                        repo['src_hashes'][pkg_name]['sha256'] = pkg_sha256
                else:
                    # load to pkg_hashes
                    for c in contents:
                        pkg_name = c.split()[1]
                        pkg_sha256 = bytes.fromhex(c.split()[0])
                        repo['pkg_hashes'][pkg_name]['sha256'] = pkg_sha256
    
    log.debug(f"Found {len(repo['src']['path'])} source directories")
    log.debug(f"Found {len(repo['comp']['comps'])} components for {len(repo['arch']['archs'])} architectures")
    log.debug(f"Found {len(repo['src_hashes'])} hasesh for 'src.rpm' files")
    log.debug(f"Found {len(repo['pkg_hashes'])} hasesh for 'rpm' files")

    return repo


def load(args):
    conn = get_client(args)
    # if not check_latest_version(conn):
    #     conn.disconnect()
    #     raise RuntimeError('Incorrect database schema version')
    # log.debug('check database version complete')
    iso = check_iso(args.path)
    if iso:
        if check_assignment_name(conn, args.pkgset):
            raise NameError('This assignment name is already loaded!')
        packages = LockedIterator(iso_find_packages(iso))
        if args.date is None:
            r = os.stat(args.path)
            args.date = datetime.datetime.fromtimestamp(r.st_mtime)
        iso_get_info(iso, args)
    else:
        connections = [conn]
        display = None
        pkgset = set()
        ts = time.time()
        # set date if None
        if args.date is None:
            args.date = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        # check if {%name%}-{%date%} already in DB
        if check_repo_date_name_in_db(conn, args.pkgset, args.date.date()):
            if not args.force:
                log.error(f"Repository with name '{args.pkgset}' and"
                          f"date '{args.date.date()}' already exists in database")
                raise NameError('This package set is already loaded!')
        log.info(f"Start loading repository structure")
        # read repo structures
        repo = read_repo_structure(args.pkgset, args.path)
        # init hash cache
        cache = init_cache(conn)
        init_hash_temp_table(conn, repo['src_hashes'])
        init_hash_temp_table(conn, repo['pkg_hashes'])
        update_hases_from_db(conn, repo['src_hashes'])
        update_hases_from_db(conn, repo['pkg_hashes'])
        ts = time.time() - ts
        log.info(f"Repository structure loaded, caches initialized in {ts:.3f} sec.")
        if args.verbose and args.repair is None:
            display = Display(log, ts)
        # store repository structure
        if args.repair is None:
            # level 0 : repository
            tmp_d = {'depth': '0', 'type': 'repo', 'size': str(len(repo['src_hashes']) + len(repo['pkg_hashes']))}
            tmp_d = join_dicts_with_as_string(tmp_d, repo['repo']['kwargs'], None)
            tmp_d = join_dicts_with_as_string(tmp_d, repo['arch']['kwargs']['all_archs'], 'archs')
            tmp_d = join_dicts_with_as_string(tmp_d, repo['comp']['kwargs']['all_comps'], 'comps')
            insert_pkgset_name(
                conn,
                name=repo['repo']['name'],
                uuid=repo['repo']['uuid'],
                puuid=repo['repo']['puuid'],
                ruuid=repo['repo']['uuid'],
                depth=0,
                tag=args.tag,
                date=args.date,
                complete=1,
                kv_args=tmp_d
            )
            repo_root = Path(repo['repo']['path'])
            # level 1 : src
            # load source RPMs first
            # generate 'src.rpm' packages list
            packages_list = []
            packages_md5 = get_packages_not_in_db_by_md5(conn)
            src_pkg_set = set()
            pkgset_cached = set()
            ts = time.time()
            pkg_count = 0
            log.info("Start checking SRC packages")
            for src_dir in repo['src']['path']:
                src_dir = Path.joinpath(repo_root, src_dir)
                if not src_dir.is_dir():
                    continue
                pkg_count_0 = 0
                pkg_count_1 = 0
                pkg_count_2 = 0
                pkg_count_3 = 0
                log.info(f"Start checking SRC packages in {'/'.join(src_dir.parts[-2:])}")
                for rpm_file in src_dir.iterdir():
                    if rpm_file.suffix == '.rpm':
                        pkg_count_0 += 1
                        if rpm_file.name in src_pkg_set:
                            pkg_count_2 += 1
                            continue
                        else:
                            src_pkg_set.add(rpm_file.name)
                            pkg_count_1 += 1
                            pkg_count += 1
                        if repo['src_hashes'][rpm_file.name]['md5'] in packages_md5:
                            # if rpm_file not in packages_list:
                            packages_list.append(str(rpm_file))
                        else:
                            pkgset_cached.add(repo['src_hashes'][rpm_file.name]['mmh'])
                            pkg_count_3 += 1
                log.info(f"Found {pkg_count_0} '.rpm' packages in '{'/'.join(src_dir.parts[-2:])}': "
                         f"{pkg_count_1} unique packages, {pkg_count_2} duplicated packages, "
                         f"{pkg_count_3} packages in cache")
            log.info(f"Checked {pkg_count} SRC packages. "
                     f"{len(packages_list)} packages for load. "
                     f"Time elapsed {(time.time() - ts):.3f} sec.")
            # load 'src.rpm' packages
            worker_pool(cache, repo['src_hashes'], repo['pkg_hashes'], packages_list, pkgset, display, True, args)
            # build pkgset for PackageSet record
            pkgset.update(pkgset_cached)

            insert_pkgset(conn, repo['src']['uuid'], pkgset)
            # store PackageSetName record for 'src'
            tmp_d = {'depth': '1', 'type': 'srpm', 'size': str(len(pkgset))}
            tmp_d = join_dicts_with_as_string(tmp_d, repo['src']['path'], 'SRPMS')
            tmp_d = join_dicts_with_as_string(tmp_d, repo['repo']['name'], 'repo')
            insert_pkgset_name(
                conn,
                name=repo['src']['name'],
                uuid=repo['src']['uuid'],
                puuid=repo['src']['puuid'],
                ruuid=repo['repo']['uuid'],
                depth=1,
                tag=args.tag,
                date=args.date,
                complete=1,
                kv_args=tmp_d
            )
            
            # level 2: architectures
            for arch in repo['arch']['archs']:
                tmp_d = {'depth': '1', 'type': 'arch', 'size': '0'}
                tmp_d = join_dicts_with_as_string(tmp_d, arch['path'], 'path')
                tmp_d = join_dicts_with_as_string(tmp_d, repo['repo']['name'], 'repo')
                insert_pkgset_name(
                    conn,
                    name=arch['name'],
                    uuid=arch['uuid'],
                    puuid=arch['puuid'],
                    ruuid=repo['repo']['uuid'],
                    depth=1,
                    tag=args.tag,
                    date=args.date,
                    complete=1,
                    kv_args=tmp_d
                )
            # level 3: components
            for comp in repo['comp']['comps']:
                # load RPMs first
                pkgset = set()
                pkgset_cached = set()
                # generate 'rpm' packages list
                packages_list = []
                packages_md5 = get_packages_not_in_db_by_md5(conn)
                ts = time.time()
                pkg_count = 0
                log.info(f"Start checking RPM packages in '{comp['path']}'")
                rpm_dir = Path.joinpath(repo_root, comp['path'])
                for rpm_file in rpm_dir.iterdir():
                    if rpm_file.suffix == '.rpm':
                        pkg_count += 1
                        if repo['pkg_hashes'][rpm_file.name]['md5'] in packages_md5:
                            packages_list.append(str(rpm_file))
                        else:
                            pkgset_cached.add(repo['pkg_hashes'][rpm_file.name]['mmh'])
                log.info(f"Checked {pkg_count} RPM packages. "
                         f"{len(packages_list)} packages for load. "
                         f"Time elapsed {(time.time() - ts):.3f} sec.")
                # load '.rpm' packages
                worker_pool(cache, repo['src_hashes'], repo['pkg_hashes'], packages_list, pkgset, display, False, args)
                # build pkgset for PackageSet record
                pkgset.update(pkgset_cached)

                insert_pkgset(conn, comp['uuid'], pkgset)
                # store PackageSetName record
                tmp_d = {'depth': '2', 'type': 'comp', 'size': str(len(pkgset))}
                tmp_d = join_dicts_with_as_string(tmp_d, comp['path'], 'path')
                tmp_d = join_dicts_with_as_string(tmp_d, repo['repo']['name'], 'repo')
                insert_pkgset_name(
                    conn,
                    name=comp['name'],
                    uuid=comp['uuid'],
                    puuid=comp['puuid'],
                    ruuid=repo['repo']['uuid'],
                    depth=2,
                    tag=args.tag,
                    date=args.date,
                    complete=1,
                    kv_args=tmp_d
                )

    # packages = LockedIterator(find_packages(args))
    # workers = []
    # connections = [conn]
    # display = None
    # if args.verbose and args.repair is None:
    #     display = Display(log)
    # cache = init_cache(conn)
    # aname = set()
    # for i in range(args.workers):
    #     conn = get_client(args)
    #     connections.append(conn)
    #     worker = Worker(conn, cache, packages, aname, display, args.repair)
    #     worker.start()
    #     workers.append(worker)

    # for w in workers:
    #     w.join()

    aname_id = str(uuid4())
    # if args.repair is None:
    #     insert_assignment_name(
    #         conn,
    #         assignment_name=args.assignment,
    #         uuid=aname_id,
    #         tag=args.tag,
    #         assignment_date=args.date,
    #         complete=1
    #     )
    #     insert_assignment(conn, aname_id, aname)

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
    parser = argparse.ArgumentParser(prog='extract',
                                     description='Load repository structure from file system or ISO image to database')
    parser.add_argument('pkgset', type=str, help='Repository name')
    parser.add_argument('path', type=str, help='Path to packages')
    parser.add_argument('-t', '--tag', type=str, help='Assignment tag', default='')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database port')
    parser.add_argument('-u', '--user', type=str, help='Database login')
    parser.add_argument('-P', '--password', type=str, help='Database password')
    parser.add_argument('-w', '--workers', type=int, help='Workers count (default: 10)')
    parser.add_argument('-D', '--debug', action='store_true', help='Set logging level to debug')
    parser.add_argument('-T', '--timing', action='store_true', help='Enable timing for functions')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-A', '--date', type=valid_date, help='Set repository datetime release. Format YYYY-MM-DD')
    parser.add_argument('-F', '--force', action='store_true',
                        help='Force to load repository with same name and date as existing one in database')
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
    logger = get_logger(NAME, args.pkgset, args.date)
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
