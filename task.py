import urllib.request
import datetime
import logging
import os.path
import argparse
import psycopg2
import rpm
import configparser
from extract import get_header, insert_package, init_cache, package_set_complete
from utils import get_logger, cvt, get_conn_str, get_logger
from manager import check_latest_version

log = get_logger('task')

class Task:
    def __init__(self, girar):
        self.db_id = None
        self.girar = girar
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

    def _get_pkg_list(self, method):
        return [i.split('\t')[-2:] for i in self.girar.get(method).split('\n') if len(i) > 0]

    def save_task(self, conn):
        if not self.fields:
            log.info('Nothing to save')
            return
        sql = 'INSERT INTO Task ({0}) VALUES ({1}) RETURNING id'
        sql = sql.format(
            ', '.join(self.fields.keys()),
            ', '.join(['%s'] * len(self.fields))
        )
        with conn.cursor() as cur:
            cur.execute(sql, tuple(self.fields.values()))
            r = cur.fetchone()
            if r:
                self.db_id = r[0]

    def save_subtasks(self, conn):
        cache = init_cache(conn, load=False)
        src_list = self._get_pkg_list('plan/add-src')
        bin_list = self._get_pkg_list('plan/add-bin')
        subtasks = {}
        for pkg, n in src_list:
            hdr = self.girar.get_header(pkg)
            pkg_id = insert_package(
                conn,
                cache,
                hdr,
                filename=os.path.basename(pkg),
                task_id=self.db_id,
                subtask=int(n)
            )
            if pkg_id:
                package_set_complete(conn, pkg_id)
            subtasks[n] = cvt(hdr[rpm.RPMDBI_SHA1HEADER])
        for pkg, n in bin_list:
            hdr = self.girar.get_header(pkg)
            pkg_id = insert_package(
                conn,
                cache,
                hdr,
                filename=os.path.basename(pkg),
                sha1srcheader=subtasks[n],
                task_id=self.db_id,
                subtask=int(n)
            )
            if pkg_id:
                package_set_complete(conn, pkg_id)

    def save(self, conn):
        self.save_task(conn)
        self.save_subtasks(conn)


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
            args.dbname = args.dbname or section_db.get('dbname', None)
            args.host = args.host or section_db.get('host', None)
            args.port = args.port or section_db.get('port', None)
            args.user = args.user or section_db.get('user', None)
            args.password = args.password or section_db.get('password', None)
    return args


def load(args, conn):
    girar = Girar(args.url)
    if girar.check():
        task = Task(girar)
        task.save(conn)
    else:
        log.info('Task not found: {0}'.format(args.url))


def main():
    args = get_args()
    conn = None
    try:
        conn = psycopg2.connect(get_conn_str(args))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        if not check_latest_version(conn):
            raise RuntimeError('Incorrect database schema version')
        load(args, conn)
    except Exception as error:
        log.error(error)
    finally:
        if conn is not None:
            conn.close()


if __name__ == '__main__':
    main()
