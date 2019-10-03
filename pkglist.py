import rpm
import os
import lzma
import bz2
import gzip
import argparse
import logging
import sys
import configparser
import clickhouse_driver as chd
from urllib import request, parse
from datetime import datetime
from utils import get_logger, mmhash, cvt
from shutil import copyfileobj
from io import BytesIO
from uuid import uuid4

NAME = 'pkglist'
ARCHS = ['aarch64', 'i586', 'noarch', 'ppc64le', 'x86_64', 'x86_64-i586']
SQL_APR_INSERT = (
    'INSERT INTO AptPkgRelease (apr_uuid, apr_hashrelease, apr_origin, '
    'apr_label, apr_suite, apr_codename, apr_arch, apr_archive, apr_date, '
    'apr_description, apr_notautomatic, apr_version, apr_component) VALUES'
)
SQL_APS_INSERT = (
    'INSERT INTO AptPkgSet (apr_uuid, aps_uuid, aps_name, aps_version, '
    'aps_release, aps_epoch, aps_serial, aps_buildtime, aps_disttag, aps_arch, '
    'aps_sourcerpm, aps_md5, aps_filesize, aps_filename) VALUES'
)
SQL_CHECK_RELEASE = (
    'SELECT COUNT(*) FROM AptPkgRelease WHERE apr_hashrelease=%(hsh)s'
)
COMPRESSORS = {
    'xz': lzma.open,
    'bz2': bz2.open,
    'gz': gzip.open
}


log = logging.getLogger(NAME)


def parse_release(content):
    strs = content.split('\n')
    data = {}
    _ps = lambda x: x.split(':', 1)[1].strip() # parse string
    _pl = lambda x: x.split(':', 1)[1].split() # parse list
    for s in strs:
        if s.startswith('Origin:'):
            data['apr_origin'] = _ps(s)
        if s.startswith('Label:'):
            data['apr_label'] = _ps(s)
        if s.startswith('Suite:'):
            data['apr_suite'] = _ps(s)
        if s.startswith('Codename:'):
            data['apr_codename'] = int(_ps(s))
        if s.startswith('Date:'):
            data['apr_date'] = datetime.strptime(
                _ps(s),
                '%a, %d %b %Y %H:%M:%S %z'
            )
        if s.startswith('Architectures:'):
            data['archs'] = _pl(s)
        if s.startswith('Components:'):
            data['components'] = _pl(s)
        if s.startswith('Description:'):
            data['apr_description'] = _ps(s)
        if s.startswith('Archive:'):
            data['apr_archive'] = _ps(s)
        if s.startswith('Component:'):
            data['apr_component'] = _ps(s)
        if s.startswith('Version:'):
            data['apr_version'] = int(_ps(s))
        if s.startswith('Architecture:'):
            data['apr_arch'] = _ps(s)
        if s.startswith('NotAutomatic:'):
            data['apr_notautomatic'] = 1 if _ps(s) == 'true' else 0
    return data


def get_client(args):
    return chd.Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password
    )


def prepare_header(hdr, apr_uuid):
    data = {
        'apr_uuid': apr_uuid,
        'aps_uuid': str(uuid4()),
        'aps_name': cvt(hdr[rpm.RPMTAG_NAME]),
        'aps_version': cvt(hdr[rpm.RPMTAG_VERSION]),
        'aps_release': cvt(hdr[rpm.RPMTAG_RELEASE]),
        'aps_epoch': cvt(hdr[rpm.RPMTAG_EPOCH], int),
        'aps_serial': cvt(hdr[rpm.RPMTAG_SERIAL], int),
        'aps_buildtime': cvt(hdr[rpm.RPMTAG_BUILDTIME]),
        'aps_disttag': cvt(hdr[rpm.RPMTAG_DISTTAG]),
        'aps_arch': cvt(hdr[rpm.RPMTAG_ARCH]),
        'aps_sourcerpm': cvt(hdr[rpm.RPMTAG_SOURCERPM]),
        'aps_md5': cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYMD5]),
        'aps_filesize': cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYFILESIZE], int),
        'aps_filename': cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYFILENAME])
    }
    return data


def load_headers(baseurl, args, release):
    conn = get_client(args)
    r, w = os.pipe()
    r, w = os.fdopen(r, 'rb', 0), os.fdopen(w, 'wb', 0)
    pid = os.fork()
    if pid:  # Parser
        w.close()
        ts = rpm.TransactionSet()
        hdrs = rpm.readHeaderListFromFD(r)
        prep_hdrs = [prepare_header(hdr, release['apr_uuid']) for hdr in hdrs]
        conn.execute(SQL_APS_INSERT, prep_hdrs)
        log.info('saved {0} headers for {1}'.format(
            len(prep_hdrs), release['apr_uuid'])
        )
        conn.disconnect()
    else:  # Decompressor
        r.close()
        conn.disconnect()
        response = get_fd(baseurl)
        if response:
            fdno = lzma.open(response, mode='rb')
            copyfileobj(fdno, w)
        os._exit(0)


def get_fd(url):
    try:
        r = request.urlopen(url)
    except Exception:
        return None
    return r


def get_bytes(url):
    r = get_fd(url)
    if r: r = r.read()
    return r


def get_content(url):
    r = get_bytes(url)
    if r: r = r.decode()
    return r


def check_release(conn, hsh):
    r = conn.execute(SQL_CHECK_RELEASE, {'hsh': hsh})
    return r[0][0] > 0


def load_release(conn, url):
    result = []
    release_content = get_bytes(url)
    if release_content:
        apr_hashrelease = mmhash(release_content)
        if check_release(conn, apr_hashrelease):
            log.info('release already loaded: {0}'.format(apr_hashrelease))
            return
        release = parse_release(release_content.decode())
        release['apr_hashrelease'] = apr_hashrelease
        for compname in release['components']:
            comp = release.copy()
            del comp['components']
            del comp['archs']
            comp['apr_uuid'] = str(uuid4())
            comp_content = get_content(url + '.' + compname)
            if comp_content:
                comp.update(parse_release(comp_content))
                result.append(comp)
    return result


def load(args):
    url = args.taskspath
    conn = get_client(args)
    for arch in ARCHS:
        if not url.endswith('/'): url = url + '/'
        baseurl = parse.urljoin(url, '{0}/base/'.format(arch))
        releases = load_release(conn, parse.urljoin(baseurl, 'release'))
        if not releases:
            log.info('releases is empty: {0}'.format(arch))
            continue
        conn.execute(SQL_APR_INSERT, releases)
        log.info('saved {0} releases'.format(len(releases)))
        for release in releases:
            pkglist_url = parse.urljoin(baseurl, 'pkglist.{0}.xz'.format(release['apr_component']))
            load_headers(pkglist_url, args, release)
    conn.disconnect()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('taskspath', type=str, nargs='?',
                        help='Path to directory with tasks')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database port')
    parser.add_argument('-u', '--user', type=str, help='Database login')
    parser.add_argument('-P', '--password', type=str, help='Database password')
    args = parser.parse_args()
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


def main():
    args = get_args()
    logger = get_logger(NAME)
    logger.setLevel(logging.DEBUG)
    try:
        load(args)
    except Exception as error:
        logger.error(error, exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

