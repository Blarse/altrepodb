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
import json
import time
import logging
import argparse
import datetime
import configparser
from pathlib import Path

from altrepodb.utils import get_logger
from altrepodb.task import TaskFromFilesystem, TaskLoadHandler, init_task_structure_from_task
from altrepodb.base import DatabaseConfig, TaskProcessorConfig
from altrepodb.database import DatabaseClient


NAME = "task"

os.environ["LANG"] = "C"


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", type=str, help="git.altlinux task url")
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
    args.workers = args.workers or 10
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


def load(args, conn, logger):
    girar = TaskFromFilesystem(args.url, logger)
    if girar.check():
        ts = time.time()
        logger.info(f"reading task structure for {args.url}")
        task_struct = init_task_structure_from_task(girar, logger)
        logger.info(f"task structure loaded in {(time.time() - ts):.3f} seconds")
        if args.dumpjson:
            p = Path.joinpath(Path.cwd(), "JSON")
            p.mkdir(exist_ok=True)
            Path.joinpath(
                p,
                f"dump-{str(task_struct['task_state']['task_id'])}-{datetime.date.today().strftime('%Y-%m-%d')}.json",
            ).write_text(json.dumps(task_struct, indent=2, sort_keys=True, default=str))
        task = TaskLoadHandler(conn, girar, logger, task_struct, args)
        logger.info(
            f"loading task {task_struct['task_state']['task_id']} to database {args.dbname}"
        )
        task.save()
        if args.flush_buffers:
            logger.info("Flushing buffer tables")
            task.flush()
        # update Depends table
        task.update_depends()
        ts = time.time() - ts
        logger.info(
            f"task {task_struct['task_state']['task_id']} loaded in {ts:.3f} seconds"
        )
    else:
        raise ValueError("task not found: {0}".format(args.url))


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    if args.url.endswith("/"):
        args.url = args.url[:-1]
    logger = get_logger(NAME, tag=(args.url.split("/")[-1]))
    if args.debug:
        logger.setLevel(logging.DEBUG)
    logger.info(f"run with args: {args}")
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
        logger.error(str(error), exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == "__main__":
    main()
