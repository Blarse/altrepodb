import argparse
import configparser
import logging
import os
import os.path
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

import clickhouse_driver as chd
import rpm

import extract
# from extract import get_header, insert_package, init_cache, check_package
from utils import get_logger, cvt, md5_from_file, mmhash, sha256_from_file

NAME = 'task'

os.environ['LANG'] = 'C'

log = logging.getLogger(NAME)


def get_client(args):
    return chd.Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password
    )


class Task:
    def __init__(self, conn, girar):
        self.girar = girar
        self.conn = conn
        self.cache = extract.init_cache(self.conn)
        self._prepare_fields()

    def _prepare_fields(self):
        self.fields = {
            'task_id': int(self.girar.get('task/id').strip()),
            'try': int(self.girar.get('task/try').strip()),
            'iteration': int(self.girar.get('task/iter').strip()),
            'status': self.girar.get('task/state').strip(),
            'is_test': self.girar.get('task/test-only', status=True),
            'branch': self.girar.get('task/repo').strip()
        }

    def _get_gears_info(self, n):
        userid = self.girar.get('gears/{0}/userid'.format(n))
        userid = userid.strip() if userid else ''
        dir_ = self.girar.get('gears/{0}/dir'.format(n))
        dir_ = dir_.strip() if dir_ else ''
        tag_name = self.girar.get('gears/{0}/tag_name'.format(n))
        tag_name = tag_name.strip() if tag_name else ''
        tag_id = self.girar.get('gears/{0}/tag_id'.format(n))
        tag_id = tag_id.strip() if tag_id else ''
        tag_author = self.girar.get('gears/{0}/tag_author'.format(n))
        tag_author = tag_author.strip() if tag_author else ''
        srpm = self.girar.get('gears/{0}/srpm'.format(n))
        srpm = srpm.strip() if srpm else ''
        try:
            type_, hash_ = self.girar.get('gears/{0}/sid'.format(n)).strip().split(':')
        except Exception as error:
            log.error(error)
            type_ = 'gear' if srpm == '' else 'srpm'
            hash_ = ''

        fields = dict(
            userid=userid,
            dir=dir_,
            tag_name=tag_name,
            tag_id=tag_id,
            tag_author=tag_author,
            srpm=srpm,
            type=type_,
            hash=hash_
        )
        return fields

    def _get_pkg_list(self, method):
        try:
            return [i.split('\t') for i in self.girar.get(method).split('\n') if len(i) > 0]
        except Exception as error:
            log.error(error)
            return []

    def _get_chroot_list(self, subtask, arch, chroot):
        method = 'build/{0}/{1}/{2}'.format(subtask, arch, chroot)
        try:
            content = self.girar.get(method)
            if content is not None:
                return [i.split('\t')[-1].strip() for i in content.split('\n') if len(i) > 0]
        except Exception as error:
            log.error(error)
        return []

    def _get_archs_list(self):
        return [i.strip() for i in self.girar.get('plan/change-arch').split('\n') if len(i) > 0]

    def _check_task(self):
        sql = ("SELECT COUNT(*) "
        "FROM Tasks WHERE task_id = %(task_id)s "
        "AND try = %(try)s "
        "AND iteration = %(iteration)s")
        already = self.conn.execute(sql, {'task_id': self.fields['task_id'], 'try': self.fields['try'], 'iteration': self.fields['iteration']})
        return already[0][0] > 0
        # return False

    def _save_task(self):
        if self._check_task():
            log.info('Task {0} already exist'.format(self.fields['task_id']))
            return
        src_pkgs = self._get_src()
        bin_pkgs = self._get_bin(src_pkgs)
        archs = self._get_archs_list()
        tasks = []
        for subtask, sha1 in src_pkgs.items():
            task = self.fields.copy()
            task.update(self._get_gears_info(subtask))
            task['subtask'] = int(subtask)
            task['sourcepkg_hash'] = mmhash(sha1)
            for arch in archs:
                task_ = task.copy()
                task_['task_arch'] = arch
                task_['pkgs'] = [mmhash(p) for p in bin_pkgs[subtask][arch]]
                # skip packages, that are not build for arch
                if len(task_['pkgs']) == 0:
                    continue
                task_['chroot_base'] = [mmhash(p) for p in self._get_chroot_list(subtask, arch, 'chroot_base')]
                task_['chroot_BR'] = [mmhash(p) for p in self._get_chroot_list(subtask, arch, 'chroot_BR')]
                tasks.append(task_)
        sql = """INSERT INTO Tasks (task_id, subtask, sourcepkg_hash, try, iteration, status,
                   is_test, branch, pkgs, userid, dir, tag_name, tag_id,
                   tag_author, srpm, type, hash, task_arch, chroot_base,
                   chroot_BR) VALUES"""
        self.conn.execute(sql, tasks)
        log.info('save task={0} try={1} iter={2}'.format(self.fields['task_id'], self.fields['try'], self.fields['iteration']))

    def _get_src(self):
        src_list = self._get_pkg_list('plan/add-src')
        src_pkgs = {}
        for *_, pkg, n in src_list:
            kw = {}
            hdr = self.girar.get_header(pkg)
            sha1 = bytes.fromhex(cvt(hdr[rpm.RPMDBI_SHA1HEADER]))
            pkghash = mmhash(sha1)
            kw['pkg_hash'] = pkghash
            kw['pkg_srcrpm_hash'] = pkghash
            kw['pkg_filename'] = Path(pkg).name
            kw['pkg_sourcerpm'] = Path(pkg).name
            # if not extract.check_package(self.cache, hdr):
            if not extract.check_package_in_cache(self.cache, pkghash):
                extract.insert_package(self.conn, hdr, **kw)
                extract.insert_pkg_hash_single(self.conn,
                    {'mmh': pkghash,
                    'sha1': sha1,
                    'md5': md5_from_file(self.girar.get_file_path(pkg), as_bytes=True),
                    'sha256': sha256_from_file(self.girar.get_file_path(pkg), as_bytes=True)}
                )
                log.info('add src package: {0}'.format(sha1.hex()))
            src_pkgs[n] = sha1
        return src_pkgs

    def _get_bin(self, src):
        bin_list = self._get_pkg_list('plan/add-bin')
        bin_pkgs = defaultdict(lambda: defaultdict(list))
        for _, _, arch, _, pkg, n, *_ in bin_list:
            kw = {}
            hdr = self.girar.get_header(pkg)
            sha1 = bytes.fromhex(cvt(hdr[rpm.RPMDBI_SHA1HEADER]))
            pkghash = mmhash(sha1)
            kw['pkg_hash'] = pkghash
            kw['pkg_srcrpm_hash'] = mmhash(src[n])
            kw['pkg_filename'] = Path(pkg).name
            # if not extract.check_package(self.cache, hdr):
            if not extract.check_package_in_cache(self.cache, pkghash):
                extract.insert_package(self.conn, hdr, **kw)
                extract.insert_pkg_hash_single(self.conn,
                    {'mmh': pkghash,
                    'sha1': sha1,
                    'md5': md5_from_file(self.girar.get_file_path(pkg), as_bytes=True),
                    'sha256': sha256_from_file(self.girar.get_file_path(pkg), as_bytes=True)}
                )
                log.info('add bin package: {0}'.format(sha1.hex()))
            bin_pkgs[n][arch].append(sha1)
        return bin_pkgs

    def save(self):
        self._save_task()


class Girar:
    def __init__(self, url):
        self.url = url
        self.ts = rpm.TransactionSet()

    def _get_content(self, url, status=False):
        try:
            r = urllib.request.urlopen(url)
        except urllib.error.URLError as e:
            log.debug('{0} - {1}'.format(e, url))
            if status:
                return False
            return None
        except Exception as e:
            log.error('{0} - {1}'.format(e, url))
            return None
        if r.getcode() == 200:
            if status:
                return True
            return cvt(r.read())

    def get(self, method, status=False):
        p = os.path.join(self.url, method)
        r = self._get_content(p, status)
        return r

    def check(self):
        return self._get_content(self.url, status=True)

    def get_header(self, path):
        return extract.get_header(self.ts, os.path.join(self.url, path))


class TaskFromFS:
    def __init__(self, url):
        self.url = Path(url)
        self.ts = rpm.TransactionSet()

    def _get_content(self, url, status=False):
        r = None
        try:
            r = Path(url).read_bytes()
        except IsADirectoryError:
            # return directory files listing
            if status:
                return True
            return [_ for _ in Path(url).iterdir() if _.is_file()]
        except FileNotFoundError as e:
            log.debug(f"{e} - {url}")
            if status:
                return False
            return None
        except Exception as e:
            log.error(f"{e} - {url}")
            return None
        if r is not None:
            if status:
                return True
            return r

    def get(self, method, status=False):
        p = Path.joinpath(self.url, method)
        r = self._get_content(p, status)
        return cvt(r)

    def get_bytes(self, method, status=False):
        p = Path.joinpath(self.url, method)
        r = self._get_content(p, status)
        return r

    def check(self):
        return self._get_content(self.url, status=True)

    def get_header(self, path):
        return extract.get_header(self.ts, str(Path.joinpath(self.url, path)))

    def get_file_path(self, path):
        return Path.joinpath(self.url, path)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str, help='git.altlinux task url')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database password')
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


def load(args, conn):
    # girar = Girar(args.url)
    girar = TaskFromFS(args.url)
    if girar.check():
        task = Task(conn, girar)
        task.save()
    else:
        raise ValueError('task not found: {0}'.format(args.url))


def main():
    args = get_args()
    logger = get_logger(NAME)
    logger.setLevel(logging.DEBUG)
    conn = None
    try:
        conn = get_client(args)
        # if not check_latest_version(conn):
        #     raise RuntimeError('incorrect database schema version')
        load(args, conn)
    except Exception as error:
        logger.error(error, exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == '__main__':
    main()
