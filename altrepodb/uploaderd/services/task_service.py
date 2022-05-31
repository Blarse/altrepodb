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

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from altrepodb.utils import cvt_datetime_local_to_utc
from altrepodb.task.processor import TaskProcessor, TaskProcessorConfig
from ..service import ServiceBase, Work, mpEvent, WorkQueue, worker_sentinel
from altrepodb.task.exceptions import TaskLoaderProcessingError, TaskLoaderError
from altrepodb.database import DatabaseClient, DatabaseConfig

NAME = "altrepodb.task_loader"
MAX_REDELIVER = 4
DEFAULT_TASKS_DIR = "/tasks"

consistent_states = ["done", "eperm", "failed", "new", "tested"]

inconsistent_states = [
    "awaiting",
    "building",
    "committing",
    "failing",
    "pending",
    "postponed",
    "swept",
]

logger = logging.getLogger(NAME)


class TaskLoaderService(ServiceBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker = task_loader_worker
        self.logger = logger

    def load_config(self):
        super().load_config()
        if "tasks_dir" not in self.config:
            self.config["tasks_dir"] = DEFAULT_TASKS_DIR

    def on_message(self, method, properties, body_json):
        if not method.routing_key == "task.state":
            # TODO: ???
            self.logger.critical("Unexpected routing key : {method.routing_key}")
            self.amqp.reject_message(method.delivery_tag, requeue=False)
            return

        headers = properties.headers
        if headers and headers.get("x-delivery-count", 0) >= MAX_REDELIVER:
            self.logger.info("Reject redelivered message")
            self.amqp.reject_message(method.delivery_tag, requeue=False)
            return

        try:
            body = json.loads(body_json)
        except json.JSONDecodeError as error:
            self.logger.error(f"Failed to decode json message: {error}")
            self.amqp.reject_message(method.delivery_tag, requeue=False)
            return

        taskid = body.get("taskid", None)
        if taskid is None:
            self.logger.error(f"Inconsistent message : {json.dumps(body)}")
            return
        taskstate = body.get("state", "unknown").lower()

        if taskstate in consistent_states or taskstate == "deleted":
            self.workers_todo_queue.put(
                Work(
                    status="new",
                    method=method,
                    properties=properties,
                    body_json=body_json,
                )
            )
        else:
            self.amqp.ack_message(method.delivery_tag)

    def on_done(self, work: Work):
        if work.status == "done":
            self.amqp.ack_message(work.method.delivery_tag)
            self.amqp.publish(work.method.routing_key, work.body_json, work.properties)
        else:
            self.amqp.reject_message(work.method.delivery_tag, requeue=False)


def task_loader_worker(
    stop_event: mpEvent,
    todo_queue: WorkQueue,
    done_queue: WorkQueue,
    dbconf: DatabaseConfig,
    config: dict[str, Any],
):
    while not stop_event.is_set():
        try:
            work = todo_queue.get()
            # exit if 'terminate' work received
            if work.status == worker_sentinel.status:
                return
        except KeyboardInterrupt:
            return

        body: dict[str, Any] = {}
        work.status = "failed"

        try:
            body = json.loads(work.body_json)
        except json.JSONDecodeError:
            logger.error("Failed to get message payload JSON")
            done_queue.put(work)
            continue

        # XXX: 'taskid' field stored as integer in AMQP message
        taskid: int = body.get("taskid", None)
        if taskid is None:
            logger.error("Failed to get Task ID from message")
            return

        taskstate = body.get("state", "unknown").lower()
        logger.debug(f"Got task {taskid} in state '{taskstate}'")
        if taskstate in consistent_states:
            if _load_task(dbconf, taskid, config["tasks_dir"]):
                work.status = "done"
        elif taskstate == "deleted":
            if _load_deleted_task(dbconf, taskid):
                work.status = "done"
        else:
            logger.warning(f"Inconsistent task state: {taskstate}")

        done_queue.put(work)


def _load_task(dbconf: DatabaseConfig, taskid: int, tasks_path: str) -> bool:

    tpconf = TaskProcessorConfig(
        id=taskid,
        path=Path(tasks_path).joinpath(str(taskid)),
        dbconfig=dbconf,
        logger=logger,
        debug=False,
    )

    try:
        tp = TaskProcessor(tpconf)
        tp.run()
        logger.info(f"Task {tpconf.id} uploaded successfully")
        return True
    except TaskLoaderProcessingError as error:
        logger.error(f"Failed to upload task {tpconf.id}: {error}")
        return False
    except TaskLoaderError as error:
        logger.error(f"Failed to upload task {tpconf.id}: {error}")
        return False
    except Exception as error:
        logger.error(f"Failed to upload task {tpconf.id}: {error}")
        return False


def _load_deleted_task(dbconf: DatabaseConfig, taskid: int) -> bool:
    insert_task_states = """
INSERT INTO TaskStates_buffer (*) VALUES
"""
    flush_tables_buffer = """
OPTIMIZE TABLE TaskStates_buffer
"""
    task_state = {
        "task_changed": cvt_datetime_local_to_utc(datetime.now()),
        "task_id": taskid,
        "task_state": "DELETED",
        "task_runby": "",
        "task_depends": [],
        "task_try": 0,
        "task_testonly": 0,
        "task_failearly": 0,
        "task_shared": 0,
        "task_message": "task deleted",
        "task_version": "",
        "task_prev": 0,
        "task_eventlog_hash": [],
    }

    conn = DatabaseClient(config=dbconf, logger=logger)
    try:
        conn.execute(insert_task_states, [task_state])
        conn.execute(flush_tables_buffer)
    except Exception as error:
        logger.error(f"{error} exception occured while saving deleted task state to DB")
        return False
    finally:
        conn.disconnect()

    return True
