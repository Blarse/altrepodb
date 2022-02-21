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

import sys
import argparse
import requests
import configparser
from typing import Any
from dateutil import tz
from requests.exceptions import RequestException
from email.utils import parsedate_to_datetime

from altrepodb.logger import LoggerProtocol, LoggerLevel, get_config_logger
from altrepodb.database import DatabaseClient, DatabaseConfig, DatabaseError

NAME = "watch"

URL_WATCH = "https://watch.altlinux.org/pub/watch/watch-total.txt"


def get_args():
    parser = argparse.ArgumentParser()
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


def load(args: Any, conn: DatabaseClient, logger: LoggerProtocol) -> None:
    logger.info("Check watch updates...")

    try:
        res = requests.get(URL_WATCH)
    except RequestException as exc:
        logger.error(f"Failed get information from {URL_WATCH}", exc_info=True)
        raise RuntimeError("Failed get information from Watch")
    watch_last_modified = parsedate_to_datetime(res.headers["Last-Modified"])

    try:
        res_db = conn.execute('SELECT max(date_update) FROM PackagesWatch')
        last_update = res_db[0][0]  # type: ignore
    except Exception as exc:
        if issubclass(exc.__class__, (DatabaseError,)):
            logger.error("Failed read data from database", exc_info=True)
            raise RuntimeError("Failed get data from database") from exc
        else:
            raise exc

    last_db_update_date = last_update.replace(tzinfo=tz.tzutc())  # type: ignore

    if watch_last_modified > last_db_update_date:
        logger.info('Loading new watch data to database...')
        data = res.text.split('\n')
        result = []
        for line in data:
            line = line.split('\t')
            if line != ['']:
                el_dict = {
                    'acl': line[0],
                    'pkg_name': line[1],
                    'old_version': line[2],
                    'new_version': line[3],
                    'url': line[4],
                    'date_update': watch_last_modified,
                }
                result.append(el_dict)

        try:
            conn.execute('INSERT INTO PackagesWatch (*) VALUES', result)
        except Exception as exc:
            if issubclass(exc.__class__, (DatabaseError,)):
                logger.error("Failed load data to database", exc_info=True)
                raise RuntimeError("Failed load data to database") from exc
            else:
                raise exc
        finally:
            logger.info("Watch data loaded to database")
    else:
        logger.info('Watch data up-to-date')


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_config_logger(
        NAME,
        tag="load",
        config=args.config,
    )
    if args.debug:
        logger.setLevel(LoggerLevel.DEBUG)
    conn = None
    try:
        conn = DatabaseClient(
            config=DatabaseConfig(
                host=args.host,
                port=args.port,
                name=args.dbname,
                user=args.user,
                password=args.password
            ),
            logger=logger
        )
        load(args, conn, logger)
    except Exception as error:
        logger.error(f"Error occurred during Watch information loading: {error}", exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == "__main__":
    main()
