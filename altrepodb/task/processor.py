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
import datetime
from pathlib import Path
from dataclasses import asdict

from altrepodb.utils import dump_to_json
from altrepodb.database import DatabaseClient
from altrepodb.exceptions import RaisingThreadError

from .base import Task, TaskProcessorConfig
from .exceptions import TaskLoaderInvalidPathError, TaskLoaderProcessingError
from .parser import TaskParser
from .loader import TaskLoadHandler


def task_as_dict(task: Task) -> dict:
    """Dumps Task class instance to dictionary representation."""

    return {
        "id": task.id,
        "arepo": task.arepo,
        "plan": asdict(task.plan),
        "state": asdict(task.state),
        "logs": [asdict(x) for x in task.logs],
        "subtasks": [asdict(x) for x in task.subtasks],
        "approvals": [asdict(x) for x in task.approvals],
        "iterations": [asdict(x) for x in task.iterations],
        "pkg_hashes": {k: asdict(v) for k, v in dict(task.pkg_hashes).items()},
    }


class TaskProcessor:
    """Process and load Task to DB."""

    def __init__(self, config: TaskProcessorConfig) -> None:
        self.conn: DatabaseClient
        self.task: Task
        self.config = config

        if self.config.logger is not None:
            self.logger = self.config.logger
        else:
            self.logger = logging.getLogger(__name__ + "." + self.__class__.__name__)

        if self.config.debug:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        self.task_parser = TaskParser(self.config.path, self.logger)
        self._check_config()

    def _check_config(self) -> None:
        # check if config is correct here
        if not self.task_parser.tf.check():
            self.logger.error(f"Invlaid task path {self.config.path}")
            raise TaskLoaderInvalidPathError(str(self.config.path))
        # create DB client and check connection
        self.conn = DatabaseClient(config=self.config.dbconfig, logger=self.logger)

    def _dump_task_to_json(self):
        p = Path.joinpath(Path.cwd(), "JSON")
        p.mkdir(exist_ok=True)
        dump_to_json(
            # FIXME: Task object dictionary contains a long integers that
            # out of JSON standard numbers range
            task_as_dict(self.task),
            Path.joinpath(
                p,
                (
                    f"dump-{str(self.task.state.task_id)}-"
                    f"{datetime.date.today().strftime('%Y-%m-%d')}.json"
                ),
            ),
        )

    def run(self) -> None:
        ts = time.time()
        self.logger.info(f"reading task structure for {self.config.path}")
        self.task = self.task_parser.read_task_structure()
        self.logger.info(f"task structure loaded in {(time.time() - ts):.3f} seconds")
        if self.config.dumpjson:
            self._dump_task_to_json()

        task_loader = TaskLoadHandler(
            task=self.task,
            conn=self.conn,
            config=self.config,
            logger=self.logger,
            taskfs=self.task_parser.tf,
        )
        self.logger.info(
            f"loading task {self.config.id} to database {self.config.dbconfig.name}"
        )

        try:
            task_loader.save()
        except RaisingThreadError as exc:
            self.logger.error(
                f"An error ocured while loding task {self.config.id} to DB"
            )
            raise TaskLoaderProcessingError(self.config.id, exc) from exc
        except Exception as exc:
            self.logger.error(
                f"An error ocured while loding task {self.config.id} to DB",
                exc_info=True,
            )
            raise exc
        else:
            ts = time.time() - ts
            self.logger.info(f"task {self.config.id} loaded in {ts:.3f} seconds")
        finally:
            self.conn.disconnect()
