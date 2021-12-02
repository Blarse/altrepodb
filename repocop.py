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

import sys
import bz2
import json
import logging
import argparse
import requests
import configparser
from dateutil import tz
from clickhouse_driver import Client, errors
from email.utils import parsedate_to_datetime
from requests.exceptions import RequestException

from utils import get_logger, get_client

NAME = "repocop"

URL_REPOCOP = "http://repocop.altlinux.org/pub/repocop/prometheus3/packages.altlinux-sisyphus.json.bz2"
FILE_NAME = URL_REPOCOP.split("/")[-1]


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


def tuples_list_to_dict(x: list) -> dict:
    res = {}
    for el in x:
        res[int(el[0])] = tuple(el[1:])

    return res


def load(args, conn: Client, logger: logging.Logger) -> None:
    logger.info("Check repocop updates...")

    try:
        res = requests.head(URL_REPOCOP)
    except RequestException as exc:
        logger.error(f"Failed get information from {URL_REPOCOP}")
        raise RuntimeError("Failed get information from Repocop") from exc

    repocop_date = parsedate_to_datetime(res.headers["Last-Modified"])

    try:
        res = conn.execute("SELECT max(rc_test_date) FROM PackagesRepocop")
        last_update = res[0][0]
    except Exception as exc:
        if issubclass(exc.__class__, (errors.Error,)):
            logger.error("Failed read data from database")
            raise RuntimeError("Failed get data from database") from exc
        else:
            raise exc

    last_db_update_date = last_update.replace(tzinfo=tz.tzutc())

    if repocop_date > last_db_update_date:
        logger.info(f"Fetching Repocop data from {URL_REPOCOP}...")
        try:
            res = requests.get(URL_REPOCOP)
            logger.info(f"URL request elapsed {res.elapsed.total_seconds():.3f}")
        except RequestException as exc:
            logger.error(f"Failed get information from {URL_REPOCOP}")
            raise RuntimeError("Failed get information from Repocop") from exc
        else:
            data = json.loads(bz2.decompress(res.content))
            logger.info(f"Got {len(data)} records from Repocop report")
            for line in data:
                line["rc_test_date"] = repocop_date
            try:
                logger.info("Loading new repocop data to database...")
                res = conn.execute("INSERT INTO PackagesRepocop (*) VALUES", data)
                logger.info(
                    f"Data loaded to database in {conn.last_query.elapsed:.3f} seconds"
                )
            except Exception as exc:
                if issubclass(exc.__class__, (errors.Error,)):
                    logger.error("Failed load data to database", exc_info=True)
                    raise RuntimeError("Failed load data to database") from exc
                else:
                    raise exc
            finally:
                logger.info("Repocop data loaded to database")
    else:
        logger.info("Repocop data is up-to-date")


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_logger(NAME, tag="load")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    conn = None
    try:
        conn = get_client(args)
        load(args, conn, logger)
    except Exception as error:
        logger.exception("Error occurred during Repocop information loading.")
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == "__main__":
    main()
