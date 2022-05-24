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

import time
import logging
import threading
import traceback
from typing import Iterator

from altrepodb.base import LockedIterator, RaisingTread, GeneratorWrapper
from altrepodb.exceptions import RaisingThreadError
from altrepodb.database import DatabaseClient

from .base import TaskLog, TaskProcessorConfig
from .reader import TaskFromFileSystem
from .file_parser import TaskFilesParser


class LogLoaderWorker(RaisingTread):
    def __init__(
        self,
        conn: DatabaseClient,
        taskfs: TaskFromFileSystem,
        taskfp: TaskFilesParser,
        logger: logging.Logger,
        logs: Iterator[TaskLog],
        count_list: list,
        *args,
        **kwargs,
    ) -> None:
        self.conn = conn
        self.taskfs = taskfs
        self.taskfp = taskfp
        self.logger = logger
        self.logs = logs
        self.count_list = count_list
        self.lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def run(self):
        self.logger.debug(f"thread {self.ident} start")
        count = 0
        for log in self.logs:
            try:
                st = time.time()
                log_start_time = self.taskfs.get_file_mtime(log.path)
                log_file_size = self.taskfs.get_file_size(log.path)
                log_file = self.taskfs.get_file_path(log.path)
                log_parsed = GeneratorWrapper(
                    self.taskfp.log_parser(log_file, log.type, log_start_time)  # type: ignore
                )
                if log_parsed:
                    count += 1
                    self.conn.execute(
                        "INSERT INTO TaskLogs_buffer (*) VALUES",
                        (
                            dict(
                                tlog_hash=log.hash,
                                tlog_line=line_,
                                tlog_ts=time_,
                                tlog_message=msg_,
                            )
                            for line_, time_, msg_ in log_parsed
                        ),
                    )
                    self.logger.debug(
                        f"Logfile loaded in {(time.time() - st):.3f} seconds "
                        f": {log.path} : {log_file_size} bytes"
                    )
                else:
                    self.logger.debug(f"Logfile parsing failed for {log.path}")
            except Exception as error:
                self.logger.error(str(error), exc_info=True)
                self.exc = error
                self.exc_message = f"Exception in thread {self.name} for log {log.path}"  # type: ignore
                self.exc_traceback = traceback.format_exc()
                break
        self.logger.debug(f"thread {self.ident} stop")
        self.count_list.append(count)


def log_load_worker_pool(
    conf: TaskProcessorConfig,
    taskfs: TaskFromFileSystem,
    logger: logging.Logger,
    logs_list: list[TaskLog],
    num_of_workers=0,
):
    # TODO: add progress bar
    st = time.time()
    taskfp = TaskFilesParser(logger)
    workers: list[RaisingTread] = []
    connections: list[DatabaseClient] = []
    logs: Iterator[TaskLog] = LockedIterator((log for log in logs_list))  # type: ignore
    logs_count: list[int] = []
    if not num_of_workers:
        num_of_workers = conf.workers

    for i in range(num_of_workers):
        conn = DatabaseClient(conf.dbconfig, logger)
        connections.append(conn)
        worker = LogLoaderWorker(
            conn=conn,
            logger=logger,
            taskfs=taskfs,
            taskfp=taskfp,
            logs=logs,
            count_list=logs_count,
        )
        worker.start()
        workers.append(worker)

    try:
        for w in workers:
            w.join()
    except RaisingThreadError as e:
        logger.error(e.message)
        raise e
    finally:
        for c in connections:
            if c is not None:
                c.disconnect()

    logger.info(
        f"{sum(logs_count)} log files loaded in {(time.time() - st):.3f} seconds"
    )
