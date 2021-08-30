import sys
import csv
import logging
import argparse
import requests
from collections import namedtuple
from clickhouse_driver import Client

from utils import get_logger

NAME = "bugzilla"
BUGZILLA_URL = "https://bugzilla.altlinux.org/buglist.cgi"
BUGZILLA_URL_PARAMS = {
    "limit": 0,
    "query_format": "advanced",
    "ctype": "csv",
    "human": 1,
    # "api_key": ""
}

log = logging.getLogger(NAME)


def get_client(args: object) -> Client:
    """Get Clickhouse client instance."""
    client = Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password,
    )
    client.connection.connect()

    return client


def get_args() -> object:
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database password")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    args = parser.parse_args()

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


def load(args: object, conn: Client) -> None:
    # get bugs CSV from Bugzilla
    log.info(f"Fetching Bugzilla data from {BUGZILLA_URL}...")
    response = requests.get(BUGZILLA_URL, params=BUGZILLA_URL_PARAMS)
    log.info(f"URL request elapsed {response.elapsed}")

    bz_from_url = {}

    if response.status_code != 200:
        raise RuntimeError(f"Failed to fetch data from Bugzilla at {BUGZILLA_URL}")

    contents = csv.reader(response.text.splitlines())
    _ = next(contents, [])  # skip CSV headers
    bz_from_url = tuples_list_to_dict(contents)
    log.info(f"Found {len(bz_from_url)} bug records")

    #  read latest data from DB
    log.info("Fetching last Bugzilla data from database...")

    sql = """
SELECT
    bz_id,
    argMax((bz_status, bz_resolution, bz_severity, bz_product, bz_component, bz_assignee, bz_reporter, bz_summary), ts)
FROM Bugzilla
GROUP BY bz_id"""

    bz_from_db = {}

    sql_res = conn.execute(sql)
    log.info(f"SQL request elapsed {conn.last_query.elapsed} seconds")
    bz_from_db = {int(el[0]): el[1] for el in sql_res}
    log.info(f"Found {len(bz_from_db)} bug records")
    # find updated bugs
    bz_diff = {}

    for k, v in bz_from_url.items():
        if k not in bz_from_db or v != bz_from_db[k]:
            bz_diff[k] = v

    log.info(f"{len(bz_diff)} records updated. Saving to database...")
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

    log.info(f"SQL request elapsed {conn.last_query.elapsed} seconds")
    log.debug(f"Inserted {sql_res} rows to 'Bugzilla' table")


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_logger(NAME, tag="load")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    conn = None
    try:
        conn = get_client(args)
        load(args, conn)
    except Exception as error:
        logger.exception("Error occurred during Bugzilla information loading.")
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == "__main__":
    main()
