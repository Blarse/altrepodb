# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021 BaseALT Ltd
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import argparse
import bz2
import configparser
import gzip
import logging
import lzma
import os
import sys
import time
from datetime import datetime
from http.client import IncompleteRead
from shutil import copyfileobj
from urllib import request, parse
from uuid import uuid4

import clickhouse_driver as chd
import rpm
from bs4 import BeautifulSoup

import htmllistparse
from utils import get_logger, mmhash, cvt

os.environ['LANG'] = 'C'

NAME = 'pkglist'
ARCHS = ['aarch64', 'i586', 'noarch', 'ppc64le', 'x86_64', 'x86_64-i586']
SQL_APR_INSERT = """INSERT INTO AptPkgRelease (apr_uuid, apr_tag, apr_hashrelease, apr_origin,
                           apr_label, apr_suite, apr_codename, apr_arch,
                           apr_archive, apr_date,
                           apr_description, apr_notautomatic, apr_version,
                           apr_component)
VALUES"""

SQL_APS_INSERT = """
    INSERT INTO AptPkgSet (apr_uuid, aps_uuid, aps_name, aps_version, 
    aps_release, aps_epoch, aps_serial, aps_buildtime, aps_disttag, aps_arch, 
    aps_sourcerpm, aps_md5, aps_filesize, aps_filename) VALUES"""

SQL_CHECK_RELEASE = (
    'SELECT COUNT(*) FROM AptPkgRelease WHERE apr_hashrelease=%(hsh)s'
)
DECOMPRESSORS = {
    '.xz': lzma.open,
    '.bz2': bz2.open,
    '.gz': gzip.open,
    '': lambda x: x
}
get_mtime = lambda p, f: int(os.stat(os.path.join(p, f)).st_mtime)

log = logging.getLogger(NAME)


def validate_url(url):
    if not url:
        raise ValueError('not valid url')
    if not parse.urlparse(url).scheme:
        raise ValueError('url must have a scheme file:// or http://')
    if not url.endswith('/'):
        url = url + '/'
    return url


def get_files_mktime(url):
    result = {}
    url = parse.urlparse(url)
    if url.scheme.startswith('file'):
        files = [(f, get_mtime(url.path, f)) for f in os.listdir(url.path)]
    elif url.scheme.startswith('http'):
        content = get_content(url.geturl())
        soup = BeautifulSoup(content, 'html.parser')
        cwd, listing = htmllistparse.parse(soup)
        if not cwd:
            log.error('Can\'t get directory listing on '
                      'given URL {0}'.format(url.geturl()))
        files = [(f.name, int(time.mktime(f.modified))) for f in listing]
    result.update(files)
    return result


def update_buildtime(prep_hdrs, baseurl, release):
    cache = None
    for hdr in prep_hdrs:
        if hdr['aps_buildtime']:
            continue
        if cache is None:
            url = parse.urljoin(
                baseurl[:-5],
                'RPMS.{0}/'.format(release['apr_component'])
            )
            cache = get_files_mktime(url)
            log.info('initialize cache for getting build time')
        new_value = cache.get(hdr['aps_filename'], None)
        if new_value is None:
            raise ValueError('can\'t get build time from cache')
        hdr['aps_buildtime'] = new_value


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
        if s.startswith('MD5Sum:'):
            break
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
        'aps_buildtime': cvt(hdr[rpm.RPMTAG_BUILDTIME], int),
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
        update_buildtime(prep_hdrs, baseurl, release)
        lh = len(prep_hdrs)
        if lh > 0:
            conn.execute(SQL_APS_INSERT, prep_hdrs)
            conn.execute(SQL_APR_INSERT, [release])
            log.info('save {0} headers for {1}'.format(lh, release['apr_uuid']))
        else:
            log.info('list headers is empty, nothing to insert {0}'.format(release['apr_uuid']))
        conn.disconnect()
    else:  # Decompressor
        r.close()
        conn.disconnect()
        for k, v in DECOMPRESSORS.items():
            pkglist_url = parse.urljoin(
                baseurl,
                'pkglist.{0}{1}'.format(release['apr_component'], k)
            )
            response = get_fd(pkglist_url)
            if response:
                fdno = v(response)
                copyfileobj(fdno, w)
                log.info('parse headers from {0}'.format(pkglist_url))
                break
            else:
                log.debug('error reading {0}'.format(pkglist_url))
        os._exit(0)


def get_fd(url):
    try:
        r = request.urlopen(url)
    except Exception:
        return None
    return r


def get_bytes(url):
    for i in range(5):
        r = get_fd(url)
        try:
            if r: r = r.read()
        except IncompleteRead as e:
            log.error('{0} for {1}'.format(e, url))
            continue
        else:
            return r
    raise SystemError('can\'t read resource {0}'.format(url))


def get_content(url):
    r = get_bytes(url)
    if r: r = r.decode()
    return r


def check_release(args, hsh):
    conn = get_client(args)
    r = conn.execute(SQL_CHECK_RELEASE, {'hsh': hsh})
    conn.disconnect()
    return r[0][0] > 0


def load_release(args, baseurl):
    url = parse.urljoin(baseurl, 'release')
    result = []
    release_content = get_bytes(url)
    if release_content:
        apr_hashrelease = mmhash(release_content)
        if check_release(args, apr_hashrelease):
            log.info('release already loaded: {0}'.format(apr_hashrelease))
            return
        release = parse_release(release_content.decode())
        release['apr_hashrelease'] = apr_hashrelease
        for compname in release['components']:
            comp = release.copy()
            del comp['components']
            del comp['archs']
            comp['apr_uuid'] = str(uuid4())
            comp['apr_tag'] = args.tag
            comp_content = get_content(url + '.' + compname)
            if comp_content:
                comp.update(parse_release(comp_content))
                result.append(comp)
    return result


def load(args):
    url = validate_url(args.taskspath)
    for arch in ARCHS:
        baseurl = parse.urljoin(url, '{0}/base/'.format(arch))
        releases = load_release(args, baseurl)
        if not releases:
            log.info('releases is empty: {0}'.format(arch))
            continue
        for release in releases:
            load_headers(baseurl, args, release)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('taskspath', type=str, nargs='?',
                        help='Path to directory with tasks')
    parser.add_argument('-t', '--tag', type=str, help='Tag name', default='')
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

