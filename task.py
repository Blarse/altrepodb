import urllib.request
import urllib.error
import sys
import datetime
import logging
import os.path
import argparse
import psycopg2
import rpm
import configparser
import clickhouse_driver as chd
from collections import defaultdict
from extract import get_header, insert_package, init_cache, check_package
from utils import get_logger, cvt
from manager import check_latest_version


NAME = 'task'

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
        self.cache = init_cache(self.conn)
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
        try:
            method = 'build/{0}/{1}/{2}'.format(subtask, arch, chroot)
            return [i.split('\t')[-1].strip() for i in self.girar.get(method).split('\n') if len(i) > 0]
        except Exception as error:
            log.error(error)
            return []

    def _get_archs_list(self):
        return [i.strip() for i in self.girar.get('plan/change-arch').split('\n') if len(i) > 0]

    def _check_task(self):
        sql = 'SELECT COUNT(*) FROM Tasks WHERE task_id=%(task_id)s AND try=%(try)s AND iteration=%(iteration)s'
        already = self.conn.execute(sql, {'task_id': self.fields['task_id'], 'try': self.fields['try'], 'iteration': self.fields['iteration']})
        return already[0][0] > 0

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
            task['sourcepkg_cs'] = sha1
            for arch in archs:
                task_ = task.copy()
                task_['task_arch'] = arch
                task_['pkgs'] = bin_pkgs[subtask][arch]
                task_['chroot_base'] = self._get_chroot_list(subtask, arch, 'chroot_base')
                task_['chroot_BR'] = self._get_chroot_list(subtask, arch, 'chroot_BR')
                tasks.append(task_)
        sql = 'INSERT INTO Tasks (task_id, subtask, sourcepkg_cs, try, iteration, status, is_test, branch, pkgs, userid, dir, tag_name, tag_id, tag_author, srpm, type, hash, task_arch, chroot_base, chroot_BR) VALUES'
        self.conn.execute(sql, tasks)
        log.info('save task={0} try={1} iter={2}'.format(self.fields['task_id'], self.fields['try'], self.fields['iteration']))

    def _get_src(self):
        src_list = self._get_pkg_list('plan/add-src')
        src_pkgs = {}
        for *_, pkg, n in src_list:
            hdr = self.girar.get_header(pkg)
            sha1 = cvt(hdr[rpm.RPMDBI_SHA1HEADER])
            if not check_package(self.cache, hdr):
                insert_package(self.conn, hdr, filename=os.path.basename(pkg))
                log.info('add src package: {0}'.format(sha1))
            src_pkgs[n] = sha1
        return src_pkgs

    def _get_bin(self, src):
        bin_list = self._get_pkg_list('plan/add-bin')
        bin_pkgs = defaultdict(lambda: defaultdict(list))
        for *_, arch, _, pkg, n in bin_list:
            hdr = self.girar.get_header(pkg)
            sha1 = cvt(hdr[rpm.RPMDBI_SHA1HEADER])
            if not check_package(self.cache, hdr):
                insert_package(self.conn, hdr, filename=os.path.basename(pkg), sha1srcheader=src[n])
                log.info('add bin package: {0}'.format(sha1))
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
        return get_header(self.ts, os.path.join(self.url, path))


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
    girar = Girar(args.url)
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
        if not check_latest_version(conn):
            raise RuntimeError('incorrect database schema version')
        load(args, conn)
    except Exception as error:
        logger.error(error, exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == '__main__':
    main()
