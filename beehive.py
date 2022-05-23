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
import json
import argparse
import configparser
from pathlib import Path

from altrepodb import get_config_logger, LoggerLevel, DatabaseConfig
from altrepodb.beehive import Beehive, BeehiveConfig, Endpoint, EndpointType


NAME = "beehive"
BEEHIVE_BASE_URL = "https://git.altlinux.org/beehive"
BEEHIVE_BRANCHES = (
    "Sisyphus",
    "p10",
    "p9",
)
BEEHIVE_ARCHS = ("i586", "x86_64")
BEEHIVE_ENDPOINTS = (
    Endpoint("latest_dir_mtime", EndpointType.DIR, "logs", "", "latest"),
    Endpoint("time_file_listing", EndpointType.FILE1, "logs", "latest/time.list", None),
    Endpoint("error_dir_listing", EndpointType.DIR, "logs", "latest/error", None),
    Endpoint("success_dir_listing", EndpointType.DIR, "logs", "latest/success", None),
    Endpoint("ftbfs_since_file_listing", EndpointType.FILE2, "stats", "ftbfs-since", None),
)


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


def dump_to_json(content, prefix: str) -> None:
    p = Path.joinpath(Path.cwd(), "JSON")
    p.mkdir(exist_ok=True)
    Path.joinpath(p, f"dump-{prefix}.json").write_text(
        json.dumps(content, indent=2, sort_keys=True, default=str)
    )


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
    logger.debug(f"Run with args: {args}")
    try:
        logger.info("Start loading data from Beehive")
        logger.info("=" * 60)
        bh = Beehive(
            config=BeehiveConfig(
                base_url=BEEHIVE_BASE_URL,
                branches=BEEHIVE_BRANCHES,
                archs=BEEHIVE_ARCHS,
                endpoints=BEEHIVE_ENDPOINTS,
                timeout=30,
                dbconfig=DatabaseConfig(
                    host=args.host,
                    port=args.port,
                    name=args.dbname,
                    user=args.user,
                    password=args.password,
                ),
                logger=logger,
            )
        )
        bh.run()
    except Exception as error:
        logger.error(
            "Error occurred during Beehive information loading: {error}", exc_info=True
        )
        sys.exit(1)
    finally:
        logger.info("=" * 60)
        logger.info("Stop loading data from Beehive")


if __name__ == "__main__":
    main()
