from datetime import datetime
import os
import sys
import logging
import argparse
import configparser
from pathlib import Path
from dataclasses import dataclass
from clickhouse_driver import Client

from utils import get_logger, cvt_datetime_local_to_utc


NAME = "task_cleaner"

os.environ["LANG"] = "C"


@dataclass
class SQL:
    get_tasks_not_done = """
SELECT DISTINCT task_id
FROM
(
    SELECT task_id, argMax(task_state, task_changed) AS state
    FROM TaskStates
    GROUP BY task_id
)
WHERE state != 'DONE'
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

    def process_tasks(self):
        # get not 'DONE' state tasks list from DB
        res = self.conn.execute(self.sql.get_tasks_not_done)
        tasks = {r[0] for r in res}
        if self.task_id:
            if self.task_id not in tasks:
                self.logger.info(f"Task {self.task_id} not found in DB. Exiting...")
                return
        else:
            tasks = set((self.task_id,))

        payload = []

        for task in tasks:
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
                    "task_version": 0,
                    "task_prev": 0,
                    "task_eventlog_hash": 0,
                }
                payload.append(task_state)
        self.logger.info(
            f"Found {len(payload)} tasks that seems to be deleted. Saving new states to DB..."
        )
        # load deleted task statuses to DB
        self.conn.execute(self.sql.insert_task_states, payload)

    def flush(self):
        """Force flush buffer tables using OPTIMIZE TABLE SQL requests."""

        self.logger.info("Flushing buffer tables")
        self.conn.execute(self.sql.flush_tables_buffer)


def get_client(args) -> Client:
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


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str, help="Path to tasks directory")
    parser.add_argument("-t", "--task-id", type=int, help="Task id")
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


def load(args, conn: Client, logger: logging.Logger) -> None:
    tc = TaskCleaner(args, conn, logger)
    tc.process_tasks()
    tc.flush()


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_logger(NAME, tag="clean")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    conn = None
    try:
        logger.info("Start checking for deleted tasks")
        logger.info("=" * 60)
        conn = get_client(args)
        if not Path(args.path).is_dir():
            raise ValueError(f"{args.path} not a directory")
        if args.task_id is not None and args.task_id <= 0:
            raise ValueError(f"Incorrect task id {args.task_id}")
        if args.task_id is None:
            args.task_id = 0
        load(args, conn, logger)
    except Exception as error:
        logger.exception("Error occurred during task processing")
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()
    logger.info("=" * 60)
    logger.info("Stop checking for deleted tasks")


if __name__ == "__main__":
    main()
