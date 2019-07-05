import urllib.request
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
            'id': int(self.girar.get('task/id').strip()),
            'try': int(self.girar.get('task/try').strip()),
            'iteration': int(self.girar.get('task/iter').strip()),
            'status': self.girar.get('task/state').strip(),
            'is_test': self.girar.get('task/test-only', status=True),
            'branch': self.girar.get('task/repo').strip()
        }

    def _get_pkg_list(self, method):
        return [i.split('\t')[-2:] for i in self.girar.get(method).split('\n') if len(i) > 0]

    def _save_task(self):
        src_pkgs = self._get_src()
        bin_pkgs = self._get_bin(src_pkgs)
        tasks = []
        for subtask, sha1 in src_pkgs.items():
            task = self.fields.copy()
            task['subtask'] = int(subtask)
            task['sourcepkg_cs'] = sha1
            task['pkgs'] = bin_pkgs[subtask]
            tasks.append(task)
        sql = 'INSERT INTO Tasks (id, subtask, sourcepkg_cs, try, iteration, status, is_test, branch, pkgs) VALUES'
        self.conn.execute(sql, tasks)

    def _get_src(self):
        src_list = self._get_pkg_list('plan/add-src')
        src_pkgs = {}
        for pkg, n in src_list:
            hdr = self.girar.get_header(pkg)
            if not check_package(self.cache, hdr):
                insert_package(self.conn, hdr, filename=os.path.basename(pkg))
            src_pkgs[n] = cvt(hdr[rpm.RPMDBI_SHA1HEADER])
        return src_pkgs

    def _get_bin(self, src):
        bin_list = self._get_pkg_list('plan/add-bin')
        bin_pkgs = defaultdict(list)
        for pkg, n in bin_list:
            hdr = self.girar.get_header(pkg)
            if not check_package(self.cache, hdr):
                insert_package(self.conn, hdr, filename=os.path.basename(pkg), sha1srcheader=src[n])
            bin_pkgs[n].append(cvt(hdr[rpm.RPMDBI_SHA1HEADER]))
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
        except Exception as e:
            log.error('{0} - {1}'.format(e, url))
            if status:
                return False
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
        log.info('task not found: {0}'.format(args.url))


def main():
    args = get_args()
    logger = get_logger(NAME)
    conn = None
    try:
        conn = get_client(args)
        if not check_latest_version(conn):
            raise RuntimeError('incorrect database schema version')
        load(args, conn)
    except Exception as error:
        logger.error(error, exc_info=True)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == '__main__':
    main()
