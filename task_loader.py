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

from altrepodb.task.processor import TaskProcessor
from altrepodb.task.base import TaskProcessorConfig
from altrepodb.logger import get_config_logger
from altrepodb.database import DatabaseConfig


NAME = "task"

os.environ["LANG"] = "C"


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str, help="Path to task directory")
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database password")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument("-w", "--workers", type=int, help="Workers count (default: 4)")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    parser.add_argument(
        "-J",
        "--dumpjson",
        action="store_true",
        help="Dump parsed task structure to JSON file",
    )
    parser.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="Force to load packages from task to database",
    )
    parser.add_argument(
        "-f",
        "--flush-buffers",
        action="store_true",
        help="Force to flush buffer tables after task loaded",
    )
    args = parser.parse_args()
    args.workers = args.workers or 4
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
            # get 'workers' from 'DEFAULT' config file section
            try:
                workers = int(section_db.get("workers", ""))
            except ValueError:
                workers = 0
            args.workers = max(workers, args.workers)
    else:
        args.dbname = args.dbname or "default"
        args.host = args.host or "localhost"
        args.port = args.port or None
        args.user = args.user or "default"
        args.password = args.password or ""
    return args


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    if args.path.endswith("/"):
        args.path = args.path[:-1]
    tag = args.path.split("/")[-1]
    logger = get_config_logger(
        NAME,
        tag=tag,
        config=args.config,
    )
    logger.info(f"Run with args: {args}")
    try:
        config = TaskProcessorConfig(
            id=int(tag),
            path=args.path,
            debug=args.debug,
            flush=args.flush_buffers,
            force=args.force,
            workers=args.workers,
            dumpjson=args.dumpjson,
            dbconfig=DatabaseConfig(
                host=args.host,
                port=args.port,
                name=args.dbname,
                user=args.user,
                password=args.password,
            ),
            logger=logger,
        )
        tp = TaskProcessor(config=config)
        tp.run()
    except Exception as error:
        logger.error(str(error), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
