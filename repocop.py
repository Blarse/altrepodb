import sys
import bz2
import json
import logging
import argparse
import requests
import configparser
from dateutil import tz
from clickhouse_driver import Client
from email.utils import parsedate_to_datetime
from clickhouse_driver import errors
from requests.exceptions import RequestException

from utils import get_logger

NAME = "repocop"

URL_REPOCOP = "http://repocop.altlinux.org/pub/repocop/prometheus3/packages.altlinux-sisyphus.json.bz2"
FILE_NAME = URL_REPOCOP.split("/")[-1]

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


def load(args: object, conn: Client) -> None:
    log.info("Check repocop updates...")

    try:
        res = requests.head(URL_REPOCOP)
    except RequestException as exc:
        log.error(f"Failed get information from {URL_REPOCOP}")
        raise RuntimeError("Failed get information from Repocop") from exc

    repocop_date = parsedate_to_datetime(res.headers["Last-Modified"])

    try:
        res = conn.execute("SELECT max(rc_test_date) FROM PackagesRepocop")
        last_update = res[0][0]
    except Exception as exc:
        if issubclass(exc.__class__, (errors.Error,)):
            log.error("Failed read data from database")
            raise RuntimeError("Failed get data from database") from exc
        else:
            raise exc

    last_db_update_date = last_update.replace(tzinfo=tz.tzutc())

    if repocop_date > last_db_update_date:
        log.info(f"Fetching Repocop data from {URL_REPOCOP}...")
        try:
            res = requests.get(URL_REPOCOP)
            log.info(f"URL request elapsed {res.elapsed.total_seconds():.3f}")
        except RequestException as exc:
            log.error(f"Failed get information from {URL_REPOCOP}")
            raise RuntimeError("Failed get information from Repocop") from exc
        else:
            data = json.loads(bz2.decompress(res.content))
            log.info(f"Got {len(data)} records from Repocop report")
            for line in data:
                line["rc_test_date"] = repocop_date
            try:
                log.info("Loading new repocop data to database...")
                res = conn.execute("INSERT INTO PackagesRepocop (*) VALUES", data)
                log.info(
                    f"Data loaded to database in {conn.last_query.elapsed:.3f} seconds"
                )
            except Exception as exc:
                if issubclass(exc.__class__, (errors.Error,)):
                    log.error("Failed load data to database", exc_info=True)
                    raise RuntimeError("Failed load data to database") from exc
                else:
                    raise exc
            finally:
                log.info("Repocop data loaded to database")
    else:
        log.info("Repocop data is up-to-date")


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
        logger.exception("Error occurred during Repocop information loading.")
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == "__main__":
    main()
