import urllib.request
import urllib.error
import htmllistparse
from bs4 import BeautifulSoup
import sys
import time
import datetime
import logging
import argparse
import configparser
import clickhouse_driver as chd
from utils import get_logger, cvt, mmhash
from collections import namedtuple
import re

NAME = 'acl'

log = logging.getLogger(NAME)


def get_client(args):
    return chd.Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password
    )


class Acl:
    def __init__(self, conn, url):
        self.url = url
        self.conn = conn
        self.loaddata = []
        self.dbhash = {}

    def _get_branch_from_filename(self, filename):
        return re.split(r'\W+', filename, 2)[2]

    def _get_list_acl(self, filename, branch):
        f = self.url.get('/{0}'.format(filename)).splitlines()
        listacl = []
        for line in f:
            # initialize set () for the branch if it does not exist in the database
            if branch not in self.dbhash.keys():
                self.dbhash[branch] = set()
            # check hash for loaded ACL exists in latest database
            if mmhash(line.translate({ord(i): None for i in ' \t'})) not in self.dbhash[branch]:
                listacl.append(line.strip().split('\t'))
        return (listacl)

    # get murmurhash from database for existing ACLs
    def _load_hash_from_db(self):
        sql = "SELECT acl_branch,murmurHash3_64(concat(acl_for,arrayStringConcat(acl_list))) FROM last_acl"
        try:
            result = self.conn.execute(sql)
        except Exception as error:
            log.error('Error with loading data from database')
            log.error(error)
            return False
        for key, value in result:
            if key not in self.dbhash.keys():
                self.dbhash[key] = set()
            self.dbhash[key].add(value)
        if not self.dbhash:
            log.info('WARNING:database is empty. First Load.')
        else:
            log.info('Loaded {n} ACLs from database'.format(n=sum(len(k) for k in self.dbhash.values())))
        return True

    def _save_branch(self, branch, date, values):
        sqlvalues = []
        sql = "INSERT INTO Acl (acl_date,acl_for,acl_branch,acl_list) VALUES"
        for value in values:
            aclvalue = {
                'acl_date': date,
                'acl_for': value[0],
                'acl_branch': branch,
                'acl_list': value[1].split(' ')
            }
            sqlvalues.append(aclvalue)
        if len(sqlvalues) > 0:
            try:
                self.conn.execute(sql, sqlvalues)
                return True
            except Exception as error:
                log.error('Error with saving data to database')
                log.error(error)
                return False

    def _put_to_database(self):
        for acl in self.loaddata:
            if acl.data:
                if not self._save_branch(acl.branch, acl.datetime, acl.data):
                    return False
        return True

    def _get_acls(self):
        a = self.url.get()
        try:
            soup = BeautifulSoup(a, 'html.parser')
            listing = htmllistparse.parse(soup)
        except Exception as error:
            log.error('Error parse URL')
            log.error(error, exc_info=True)
            return False

        AclData = namedtuple('AclData', ['branch', 'datetime', 'data'])
        if not listing[0]:
            log.error('Can\'t get directory listing on given URL {url}'.format(url=self.url.url))
            return False
        for i in listing[1]:
            filename = i.name
            if not filename: continue
            file_date = datetime.datetime.fromtimestamp(time.mktime(i.modified))
            if filename.startswith('list.groups') or filename.startswith('list.packages'):
                branch = self._get_branch_from_filename(filename)
                self.loaddata.append(AclData(branch, file_date, self._get_list_acl(filename, branch)))
        if self.loaddata:
            return True
        else:
            log.error('Can\'t find files with ACL listing on given URL {url}'.format(url=self.url.url))
            return False

    def _save_acl(self):
        if not self._load_hash_from_db():
            return False
        if not self._get_acls():
            return False
        if not self._put_to_database():
            return False
        log.info('Saved {n} updated ACLs from {url}'
                 .format(n=sum(len(acl.data) for acl in self.loaddata),
                         url=self.url.url))
        return True

    def save(self):
        self._save_acl()


class Url:
    def __init__(self, url):
        log.debug('{0}'.format(url))
        self.url = url

    def _get_content(self, url=False, status=False):
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

    def get(self, method=False, status=False):
        if method:
            p = self.url + method
        else:
            p = self.url
        log.debug('URL: {0}'.format(p))
        r = self._get_content(p, status)
        return r

    def check(self):
        return self._get_content(self.url, status=True)


def get_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', type=str, default='http://git.altlinux.org/acl', nargs='?',
                        help='git.altlinux ACL directory url')
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str, help='git.altlinux acl directory url')
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


def set_config(args):
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        # database
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
    url = Url(args.url)
    if url.check():
        acl = Acl(conn, url)
        acl.save()
    else:
        raise ValueError('Can\'t parse URL: {0}'.format(args.url))


def main():
    args = get_args()
    args = set_config(args)
    logger = get_logger(NAME)
    logger.setLevel(logging.DEBUG)
    conn = None
    try:
        conn = get_client(args)
        load(args, conn)
    except Exception as error:
        logger.error(error, exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == '__main__':
    main()
