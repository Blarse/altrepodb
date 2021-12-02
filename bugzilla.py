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
import csv
import logging
import argparse
import requests
import configparser
from collections import namedtuple
from clickhouse_driver import Client

from utils import get_logger, get_client

NAME = "bugzilla"
BUGZILLA_URL = "https://bugzilla.altlinux.org/buglist.cgi"
BUGZILLA_URL_PARAMS = {
    "limit": 0,
    "query_format": "advanced",
    "ctype": "csv",
    "human": 1,
    # "api_key": ""
}


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
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
        if cfg.has_section('DATABASE'):
            section_db = cfg['DATABASE']
            args.dbname = args.dbname or section_db.get('dbname', 'default')
            args.host = args.host or section_db.get('host', 'localhost')
            args.port = args.port or section_db.get('port', None)
            args.user = args.user or section_db.get('user', 'default')
            args.password = args.password or section_db.get('password', '')
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
    # get bugs CSV from Bugzilla
    logger.info(f"Fetching Bugzilla data from {BUGZILLA_URL}...")
    response = requests.get(BUGZILLA_URL, params=BUGZILLA_URL_PARAMS)
    logger.info(f"URL request elapsed {response.elapsed.total_seconds():.3f}")

    bz_from_url = {}

    if response.status_code != 200:
        raise RuntimeError(f"Failed to fetch data from Bugzilla at {BUGZILLA_URL}")

    contents = csv.reader(response.text.splitlines())
    _ = next(contents, [])  # skip CSV headers
    bz_from_url = tuples_list_to_dict(contents)
    logger.info(f"Found {len(bz_from_url)} bug records")

    #  read latest data from DB
    logger.info("Fetching last Bugzilla data from database...")

    sql = """
SELECT
    bz_id,
    argMax((bz_status, bz_resolution, bz_severity, bz_product, bz_component, bz_assignee, bz_reporter, bz_summary), ts)
FROM Bugzilla
GROUP BY bz_id"""

    bz_from_db = {}

    sql_res = conn.execute(sql)
    logger.info(f"SQL request elapsed {conn.last_query.elapsed:.3f} seconds")
    bz_from_db = {int(el[0]): el[1] for el in sql_res}
    logger.info(f"Found {len(bz_from_db)} bug records")
    # find updated bugs
    bz_diff = {}

    for k, v in bz_from_url.items():
        if k not in bz_from_db or v != bz_from_db[k]:
            bz_diff[k] = v
    if not bz_diff:
        logger.info(f"No bug updates found. Exiting...")
    else:
        logger.info(f"{len(bz_diff)} records updated. Saving to database...")
        # store updated bugs to database
        BugzillaRecord = namedtuple(
            "BugzillaRecord",
            (
                "bz_id",
                "bz_status",
                "bz_resolution",
                "bz_severity",
                "bz_product",
                "bz_component",
                "bz_assignee",
                "bz_reporter",
                "bz_summary",
            ),
        )
        payload_gen = (BugzillaRecord(k, *v)._asdict() for k, v in bz_diff.items())
        sql_res = conn.execute("INSERT INTO Bugzilla (*) VALUES", payload_gen)

        logger.info(f"SQL request elapsed {conn.last_query.elapsed:.3f} seconds")
        logger.debug(f"Inserted {sql_res} rows to 'Bugzilla' table")


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
        logger.exception("Error occurred during Bugzilla information loading.")
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == "__main__":
    main()
