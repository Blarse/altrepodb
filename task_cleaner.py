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

from datetime import datetime
import os
import sys
import argparse
import configparser
from pathlib import Path
from dataclasses import dataclass

from altrepodb.utils import get_logger, cvt_datetime_local_to_utc
from altrepodb.logger import LoggerProtocol
from altrepodb.database import DatabaseClient, DatabaseConfig, DatabaseError


NAME = "task_cleaner"
UNCLEAR_STATES_FILE = "unclear_state_tasks.log"

os.environ["LANG"] = "C"


@dataclass
class SQL:
    get_tasks_not_done = """
SELECT DISTINCT
    task_id,
    state
FROM
(
    SELECT task_id, argMax(task_state, task_changed) AS state
    FROM TaskStates
    GROUP BY task_id
)
WHERE state NOT IN ('DONE', 'DELETED')
ORDER BY task_id
"""

    insert_task_states = """
INSERT INTO TaskStates_buffer (*) VALUES
"""

    flush_tables_buffer = """
OPTIMIZE TABLE TaskStates_buffer
"""


class TaskCleaner:
    """"""

    def __init__(self, args, conn, logger) -> None:
        self.sql = SQL()
        self.conn = conn
        self.logger = logger
        self.path = Path(args.path)
        self.task_id = args.task_id
        self.dry_run = args.dry_run

    def process_tasks(self):
        # get not 'DONE' state tasks list from DB
        res = self.conn.execute(self.sql.get_tasks_not_done)
        tasks = {r[0]: r[1] for r in res}
        if self.task_id:
            if self.task_id not in tasks:
                self.logger.info(f"Task {self.task_id} not found in DB. Exiting...")
                return
            else:
                tasks = {self.task_id: tasks[self.task_id]}

        payload = []
        unclear_state_tasks = []

        for task in tasks.keys():
            # check if task exists on FS
            if not self.path.joinpath(str(task)).is_dir():
                # add task data with state 'DELETED' to payload
                self.logger.debug(
                    f"Task {task} not found in {str(self.path)}. Processing it as deleted one"
                )
                task_state = {
                    "task_changed": cvt_datetime_local_to_utc(datetime.now()),
                    "task_id": task,
                    "task_state": "DELETED",
                    "task_runby": "",
                    "task_depends": [],
                    "task_try": 0,
                    "task_testonly": 0,
                    "task_failearly": 0,
                    "task_shared": 0,
                    "task_message": "task found as deleted by task_cleaner",
                    "task_version": "",
                    "task_prev": 0,
                    "task_eventlog_hash": [],
                }
                payload.append(task_state)
            else:
                # check actual task state and compare to DB
                state_db = tasks[task]
                state_fs = ""
                try:
                    state_fs = (
                        self.path.joinpath(str(task), "task/state")
                        .read_text(encoding="latin-1")
                        .strip()
                    )
                except FileNotFoundError as e:
                    self.logger.debug(f"State file not found for task {task}")
                except Exception as e:
                    self.logger.error(
                        f"{e} exception occured while reading task {task} state file"
                    )
                if state_db != state_fs:
                    self.logger.info(
                        f"Task {task} state difference found:\t@DB\t{state_db}\t@FS\t{state_fs}"
                    )
                    unclear_state_tasks.append((task, state_db, state_fs))

        self.logger.info(f"Found {len(payload)} tasks that seems to be deleted")
        if not self.dry_run and len(payload):
            # load deleted task statuses to DB
            self.logger.info("Saving new task states to DB...")
            self.conn.execute(self.sql.insert_task_states, payload)

        self.logger.info(f"Found {len(unclear_state_tasks)} tasks with unclear state")
        if len(unclear_state_tasks):
            self.logger.info(
                f"Saving tasks with unclear state to '{UNCLEAR_STATES_FILE}' file..."
            )
            # save tasks with unclear state to TSV file
            with open(Path.cwd().joinpath(UNCLEAR_STATES_FILE), "wt") as f:
                for t in unclear_state_tasks:
                    f.write(f"{t[0]}\t@DB\t{t[1]}\t@FS\t{t[2]}\n")

    def flush(self):
        """Force flush buffer tables using OPTIMIZE TABLE SQL requests."""

        self.logger.info("Flushing buffer tables")
        self.conn.execute(self.sql.flush_tables_buffer)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str, help="Path to tasks directory")
    parser.add_argument("-t", "--task-id", type=int, help="Task id")
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database port")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument(
        "-x",
        "--dry-run",
        action="store_true",
        help="Dry run without recording changes to DB",
    )
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


def load(args, conn: DatabaseClient, logger: LoggerProtocol) -> None:
    tc = TaskCleaner(args, conn, logger)
    tc.process_tasks()
    if not args.dry_run:
        tc.flush()


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_logger(NAME, tag="clean")
    if args.debug:
        logger.setLevel("DEBUG")
    conn = None
    try:
        logger.info("Start checking for deleted tasks")
        logger.info("=" * 60)
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
        if not Path(args.path).is_dir():
            raise ValueError(f"{args.path} not a directory")
        if args.task_id is not None and args.task_id <= 0:
            raise ValueError(f"Incorrect task id {args.task_id}")
        if args.task_id is None:
            args.task_id = 0
        load(args, conn, logger)
    except Exception as error:
        logger.error(f"Error occurred during task processing: {error}", exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()
    logger.info("=" * 60)
    logger.info("Stop checking for deleted tasks")


if __name__ == "__main__":
    main()
