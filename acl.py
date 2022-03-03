# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021-2022 BaseALT Ltd
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

import re
import sys
import time
import argparse
import datetime
import configparser
import urllib.error
import urllib.request
import clickhouse_driver as chd
from bs4 import BeautifulSoup
from collections import namedtuple
from dataclasses import dataclass

import altrepodb.htmllistparse as htmllistparse
from altrepodb.utils import cvt, mmhash
from altrepodb.logger import LoggerLevel, LoggerProtocol, get_config_logger
from altrepodb.database import DatabaseClient, DatabaseConfig

NAME = "acl"


class Url:
    def __init__(self, url: str, timeout: int, logger: LoggerProtocol):
        self.url = url
        self.log = logger
        self.timeout = timeout
        self.log.debug("{0}".format(url))

    def _get_content(self, url, status=False):
        try:
            r = urllib.request.urlopen(url, timeout=self.timeout)
        except urllib.error.URLError as e:
            self.log.debug("{0} - {1}".format(e, url))
            if status:
                return False
            return None
        except Exception as e:
            self.log.error("{0} - {1}".format(e, url))
            return None
        if r.getcode() == 200:
            if status:
                return True
            return cvt(r.read())

    def get(self, method=None, status=False):
        if method:
            p = self.url + method
        else:
            p = self.url
        self.log.debug("URL: {0}".format(p))
        r = self._get_content(p, status)
        return r

    def check(self):
        return self._get_content(self.url, status=True)


class Acl:
    def __init__(self, url: Url, conn: DatabaseClient, logger: LoggerProtocol):
        self.url = url
        self.conn = conn
        self.log = logger
        self.loaddata = []
        self.dbhash = {}

    def _get_branch_from_filename(self, filename):
        """
        Parse branch name from ACL filename.
        """
        return re.split(r"\W+", filename, 2)[2]

    def _get_list_acl(self, filename, branch):
        """
        Download and parse for update ACL's from URL
        :param filename: URL for filename with ACL
        :param branch: key for URL branch
        :return: structure ACL for updated ACL's
        """
        f = self.url.get("/{0}".format(filename)).splitlines()  # type: ignore
        listacl = []
        for line in f:
            # initialize set () for the branch if it does not exist in the database
            if branch not in self.dbhash.keys():
                self.dbhash[branch] = set()
            # check hash for loaded ACL exists in latest database
            if (
                mmhash(line.translate({ord(i): None for i in " \t"}))
                not in self.dbhash[branch]
            ):
                listacl.append(line.strip().split("\t"))
        return listacl

    def _load_hash_from_db(self):
        """
        get murmurhash from database for latest existing ACLs
        :return: False if parsed with errors else True
        """
        sql = """SELECT acl_branch, 
           murmurHash3_64(concat(acl_for,arrayStringConcat(acl_list)))
            FROM last_acl"""
        try:
            result = self.conn.execute(sql)
        except Exception as error:
            self.log.error("Error with loading data from database")
            self.log.error(error)  # type: ignore
            return False
        # add loaded hashes to local list of sets [branch].set(hash)
        for key, value in result:
            if key not in self.dbhash.keys():
                self.dbhash[key] = set()
            self.dbhash[key].add(value)
        if not self.dbhash:
            self.log.warning("Database is empty. First Load.")
        else:
            self.log.info(
                "Loaded {n} ACLs from database"
                "".format(n=sum(len(k) for k in self.dbhash.values()))
            )
        return True

    def _save_branch(self, branch, date, values):
        """
        Save updates to database for specified branch
        :param branch: - branch name
        :param date: - update datetime
        :param values: ACL's to save
        :return: False/True
        """
        sqlvalues = []
        # always only insert Acl to database
        sql = "INSERT INTO Acl (acl_date,acl_for,acl_branch,acl_list) VALUES"
        for value in values:
            aclvalue = {
                "acl_date": date,
                "acl_for": value[0],
                "acl_branch": branch,
                "acl_list": value[1].split(" "),
            }
            sqlvalues.append(aclvalue)
        if len(sqlvalues) > 0:
            try:
                self.conn.execute(sql, sqlvalues)
                return True
            except Exception as error:
                self.log.error("Error with saving data to database")
                self.log.error(error)  # type: ignore
                return False

    def _put_to_database(self):
        """
        Save all loaded data for every branch to database
        :return: True/False
        """
        for acl in self.loaddata:
            if acl.data:
                if not self._save_branch(acl.branch, acl.datetime, acl.data):
                    return False
        return True

    def _get_acls(self):
        """
        Get all ACL's from URL
        :return: True/False
        """
        a = self.url.get()
        # html listing parser
        try:
            soup = BeautifulSoup(a, "html.parser")
            listing = htmllistparse.parse(soup)
        except Exception as error:
            self.log.error("Error parse URL")
            self.log.error(error, exc_info=True)  # type: ignore
            return False
        if not listing[0]:
            self.log.error(
                "Can't get directory listing on "
                "given URL {url}".format(url=self.url.url)
            )
            return False
        # process files from listing
        AclData = namedtuple("AclData", ["branch", "datetime", "data"])
        for i in listing[1]:
            filename = i.name
            # skip empty lines (sometimes on bad connect the lines are empty)
            if not filename:
                continue
            # get the ACL modification date and time
            file_date = datetime.datetime.fromtimestamp(time.mktime(i.modified))
            # proccess only groups and packages listing
            if filename.startswith("list.groups") or filename.startswith(
                "list.packages"
            ):
                branch = self._get_branch_from_filename(filename)
                # append to loading only modified ACL
                self.loaddata.append(
                    AclData(branch, file_date, self._get_list_acl(filename, branch))
                )

        if self.loaddata:
            return True
        else:
            self.log.error(
                "Can't find files with ACL "
                "listing on given URL {url}".format(url=self.url.url)
            )
            return False

    def _save_acl(self):
        # load hashtable with last ACL from database
        if not self._load_hash_from_db():
            return False
        # get modificated ACL's from web
        if not self._get_acls():
            return False
        # save new ACL's to DB
        if not self._put_to_database():
            return False
        self.log.info(
            "Saved {n} updated ACLs from {url}".format(
                n=sum(len(acl.data) for acl in self.loaddata), url=self.url.url
            )
        )
        return True

    def save(self):
        self._save_acl()


class AclError(Exception):
    pass


@dataclass
class AclConfig:
    url: str
    logger: LoggerProtocol
    dbconfig: DatabaseConfig
    timeout: int = 10


class AclProcessor:
    def __init__(self, config: AclConfig) -> None:
        self.logger = config.logger
        self._url = config.url
        self.url = Url(config.url, config.timeout, self.logger)
        self.conn = DatabaseClient(config.dbconfig, self.logger)

    def run(self) -> None:
        self.logger.info(f"Collect ACL information from {self._url}")
        if not self.url.check():
            raise AclError(f"Failed to parse URL: {self._url}")
        try:
            acl = Acl(self.url, self.conn, self.logger)
            acl.save()
            self.logger.info("ACL data loaded to database")
        except Exception as e:
            raise AclError("Error occured while processimg ACL") from e
        finally:
            self.conn.disconnect()


def get_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "url",
        type=str,
        default="http://git.altlinux.org/acl",
        nargs="?",
        help="git.altlinux ACL directory url",
    )
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database password")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    args = parser.parse_args()
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        if cfg.has_section("DATABASE"):
            section_db = cfg["DATABASE"]
            args.dbname = args.dbname or section_db.get("dbname", "default")
            args.host = args.host or section_db.get("host", "localhost")
            args.port = args.port or section_db.get("port", None)
            args.user = args.user or section_db.get("user", "default")
            args.password = args.password or section_db.get("password", "")
    else:
        args.dbname = args.dbname or "default"
        args.host = args.host or "localhost"
        args.port = args.port or None
        args.user = args.user or "default"
        args.password = args.password or ""
    return args


def set_config(args):
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        # database
        if cfg.has_section("DATABASE"):
            section_db = cfg["DATABASE"]
            args.dbname = args.dbname or section_db.get("dbname", "default")
            args.host = args.host or section_db.get("host", "localhost")
            args.port = args.port or section_db.get("port", None)
            args.user = args.user or section_db.get("user", "default")
            args.password = args.password or section_db.get("password", "")
    else:
        args.dbname = args.dbname or "default"
        args.host = args.host or "localhost"
        args.port = args.port or None
        args.user = args.user or "default"
        args.password = args.password or ""
    return args


def main():
    args = get_args()
    args = set_config(args)
    logger = get_config_logger(
        NAME,
        tag="load",
        config=args.config,
    )
    if args.debug:
        logger.setLevel(LoggerLevel.DEBUG)
    logger.info(f"Run with args: {args}")
    try:
        acl = AclProcessor(
            AclConfig(
                url=args.url,
                logger=logger,
                dbconfig=DatabaseConfig(
                    host=args.host,
                    port=args.port,
                    name=args.dbname,
                    user=args.user,
                    password=args.password,
                ),
            )
        )
        acl.run()
    except Exception as error:
        logger.error(str(error), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
