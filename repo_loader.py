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

import os
import sys
import argparse
import configparser

from altrepodb import get_config_logger, DatabaseConfig
from altrepodb.utils import valid_date
from altrepodb.repo import RepoProcessor, RepoProcessorConfig

NAME = "repo"

os.environ["LANG"] = "C"


def get_args():
    parser = argparse.ArgumentParser(
        prog="repo_loader",
        description="Load repository structure from file system to database",
    )
    parser.add_argument("pkgset", type=str, help="Repository name")
    parser.add_argument("path", type=str, help="Path to packages")
    parser.add_argument("-t", "--tag", type=str, help="Assignment tag", default="")
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database port")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument("-w", "--workers", type=int, help="Workers count (default: 10)")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose mode"
    )
    parser.add_argument(
        "-A",
        "--date",
        type=valid_date,
        help="Set repository datetime release. Format YYYY-MM-DD",
    )
    parser.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="Force to load repository with same name and date as existing one in database",
    )
    return parser.parse_args()


def get_config(args):
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        # default
        args.workers = args.workers or cfg["DEFAULT"].getint("workers", 10)
        # database
        if cfg.has_section("DATABASE"):
            section_db = cfg["DATABASE"]
            args.dbname = args.dbname or section_db.get("dbname", "default")
            args.host = args.host or section_db.get("host", "localhost")
            args.port = args.port or section_db.get("port", None)
            args.user = args.user or section_db.get("user", "default")
            args.password = args.password or section_db.get("password", "")
    else:
        args.workers = args.workers or 10
        args.dbname = args.dbname or "default"
        args.host = args.host or "localhost"
        args.port = args.port or None
        args.user = args.user or "default"
        args.password = args.password or ""
    return args


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    args = get_config(args)
    # avoid repository name accidentally contains capital letters
    args.pkgset = args.pkgset.lower()
    logger = get_config_logger(
        NAME,
        tag=args.pkgset,
        date=args.date,
        config=args.config,
    )
    logger.info(f"Run with args: {args}")
    try:
        config = RepoProcessorConfig(
            name=args.pkgset,
            path=args.path,
            date=args.date,
            tag=args.tag,
            debug=args.debug,
            force=args.force,
            verbose=args.verbose,
            workers=args.workers,
            dbconfig=DatabaseConfig(
                host=args.host,
                port=args.port,
                name=args.dbname,
                user=args.user,
                password=args.password,
            ),
            logger=logger,
        )
        rp = RepoProcessor(config=config)
        rp.run()
    except Exception as error:
        logger.error(str(error), exc_info=True)


if __name__ == "__main__":
    main()
