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

import os
import sys
import argparse
import configparser
from pathlib import Path
from dataclasses import dataclass

from altrepodb.base import ISOProcessorConfig, LoggerProtocol
from altrepodb.iso import ISOProcessor
from altrepodb.database import DatabaseConfig
from altrepodb.utils import (
    get_logger,
    valid_date,
)

NAME = "iso"

os.environ["LANG"] = "C"


def get_args():
    parser = argparse.ArgumentParser(
        prog="iso_loader",
        description="Load ISO image structure to database",
    )
    parser.add_argument("path", type=str, help="Path to ISO image file")
    parser.add_argument("name", type=str, help="ISO image name")
    parser.add_argument("date", type=valid_date, help="ISO image date")
    parser.add_argument("branch", type=str, help="ISO image base branch name")
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database password")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    parser.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="Force to load packages to database",
    )
    parser.add_argument(
        "-t",
        "--dry-run",
        action="store_true",
        help="Do not load data to database",
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


def load(args, dbconfig: DatabaseConfig, logger: LoggerProtocol) -> None:
    config = ISOProcessorConfig(
        name=args.name,
        date=args.date,
        path=args.path,
        branch=args.branch,
        logger=logger,
        dbconfig=dbconfig,
        debug=args.debug,
        force=args.force,
        dryrun=args.dry_run,
    )
    iso = ISOProcessor(config)
    iso.run()


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_logger(NAME, tag="load")
    if args.debug:
        logger.setLevel("DEBUG")
    conn = None
    try:
        logger.info("Start loading ISO image to database")
        logger.info("=" * 60)
        config=DatabaseConfig(
            host=args.host,
            port=args.port,
            name=args.dbname,
            user=args.user,
            password=args.password
        )
        if not Path(args.path).is_file():
            raise ValueError(f"{args.path} is not a file")
        load(args, config, logger)
    except Exception as error:
        logger.error(f"Error occurred during ISO image loading: {error}", exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()
    logger.info("=" * 60)
    logger.info("Stop loading ISO image to database")


if __name__ == "__main__":
    main()
