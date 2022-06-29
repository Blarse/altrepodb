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
import base64
import logging
from datetime import datetime
from pathlib import Path
from typing import Any
from setproctitle import setproctitle

from altrepodb.utils import cvt_datetime_local_to_utc
from altrepodb.task.processor import TaskProcessor, TaskProcessorConfig
from ..service import ServiceBase, Work, mpEvent, WorkQueue, worker_sentinel
from ..base import NotifierMessageType, NotifierMessageSeverity
from altrepodb.task.exceptions import TaskLoaderProcessingError, TaskLoaderError
from altrepodb.database import DatabaseClient, DatabaseConfig
from altrepodb.utils import set_datetime_timezone_to_utc

NAME = "altrepodb.task_loader"
ROUTING_KEYS = ("task.state", "task.subtask.approve", "task.subtask.disapprove")
TASK_STATE_RKEY = "task.state"
MAX_REDELIVER = 2
DEFAULT_TASKS_DIR = "/tasks"
LOAD_APPROVALS_FROM_FS = False
LOAD_LOGS_FOR_NEW_TASKS = False

CONSISTENT_TASK_STATES = ("done", "eperm", "failed", "new", "tested")
DELETED_TASK_STATE = "deleted"
INCONSISTENT_TASK_STATES = (
    "awaiting",
    "building",
    "committing",
    "failing",
    "pending",
    "postponed",
    "swept",
)

logger = logging.getLogger(NAME)


class TaskLoaderService(ServiceBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker = task_loader_worker
        self.logger = logger

    def load_config(self):
        super().load_config()

        self.routing_key = self.config.get("routing_key", TASK_STATE_RKEY)
        self.routing_keys = self.config.get("routing_keys", ROUTING_KEYS)
        self.publish_on_done = self.config.get("publish_on_done", False)
        self.requeue_on_reject = self.config.get("requeue_on_reject", False)
        self.max_redeliver_count = self.config.get("max_redeliver_count", MAX_REDELIVER)

        if "tasks_dir" not in self.config:
            self.config["tasks_dir"] = DEFAULT_TASKS_DIR

    def on_message(self, method, properties, body_json):
        if method.routing_key not in self.routing_keys:
            self.logger.critical(f"Unexpected routing key : {method.routing_key}")
            self.amqp.reject_message(method.delivery_tag, requeue=False)
            return

        headers = properties.headers
        if headers and headers.get("x-delivery-count", 0) > self.max_redeliver_count:
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

        if taskstate in CONSISTENT_TASK_STATES or taskstate == DELETED_TASK_STATE:
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
            if self.publish_on_done:
                self.amqp.publish(
                    work.method.routing_key, work.body_json, work.properties  # type: ignore
                )
        else:
            self.amqp.reject_message(
                work.method.delivery_tag, requeue=self.requeue_on_reject
            )
            self.report(
                reason="notify",
                payload={
                    "reason": work.reason,
                    "type": NotifierMessageType.SERVICE_WORKER_ERROR,
                    "severity": NotifierMessageSeverity.CRITICAL,
                    "work_body": work.body_json,
                },
            )


def task_loader_worker(
    stop_event: mpEvent,
    todo_queue: WorkQueue,
    done_queue: WorkQueue,
    dbconf: DatabaseConfig,
    config: dict[str, Any],
):
    setproctitle("task_loader_worker")
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
            work.reason = "Failed to get message payload JSON"
            done_queue.put(work)
            continue

        taskid: int = body.get("taskid", None)
        if taskid is None:
            logger.error("Failed to get Task ID from message")
            work.reason = "Failed to get Task ID from message"
            done_queue.put(work)
            continue

        if work.method.routing_key == config.get("routing_key", ""):
            taskstate = body.get("state", "unknown").lower()
            logger.debug(f"Got task {taskid} in state '{taskstate}'")
            if taskstate in CONSISTENT_TASK_STATES:
                state, error_message = _load_task(dbconf, taskid, config["tasks_dir"])
                if state:
                    work.status = "done"
                else:
                    work.reason = error_message
            elif taskstate == DELETED_TASK_STATE:
                state, error_message = _load_deleted_task(dbconf, taskid)
                if state:
                    work.status = "done"
                else:
                    work.reason = error_message
            else:
                logger.warning(f"Inconsistent task state: {taskstate}")
        else:
            subtaskid = body.get("subtaskid", 0)
            logger.debug(f"Got task approval message for {taskid}.{subtaskid}")
            state, error_message = _load_task_approval(dbconf, body)
            if state:
                work.status = "done"
            else:
                work.reason = error_message

        done_queue.put(work)


def _load_task(
    dbconf: DatabaseConfig, taskid: int, tasks_path: str
) -> tuple[bool, str]:

    tpconf = TaskProcessorConfig(
        id=taskid,
        path=Path(tasks_path).joinpath(str(taskid)),
        dbconfig=dbconf,
        logger=logger,
        debug=False,
        store_approvals=LOAD_APPROVALS_FROM_FS,
        store_logs_for_new=LOAD_LOGS_FOR_NEW_TASKS,
    )

    error_message = ""
    state = False

    try:
        tp = TaskProcessor(tpconf)
        tp.run()
        logger.info(f"Task {tpconf.id} uploaded successfully")
        state = True
    except TaskLoaderProcessingError as error:
        error_message = f"Failed to upload task {tpconf.id}: {error}"
    except TaskLoaderError as error:
        error_message = f"Failed to upload task {tpconf.id}: {error}"
    except Exception as error:
        error_message = f"Failed to upload task {tpconf.id}: {error}"

    if error_message:
        logger.error(error_message)
    return state, error_message


def _load_deleted_task(dbconf: DatabaseConfig, taskid: int) -> tuple[bool, str]:
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

    state = False
    error_message = ""

    conn = DatabaseClient(config=dbconf, logger=logger)
    try:
        conn.execute(insert_task_states, [task_state])
        conn.execute(flush_tables_buffer)
        state = True
    except Exception as error:
        logger.error(f"{error} exception occured while saving deleted task state to DB")
        error_message = (
            f"{error} exception occured while saving deleted task state to DB"
        )
    finally:
        conn.disconnect()

    return state, error_message


def _load_task_approval(
    dbconf: DatabaseConfig, body: dict[str, Any]
) -> tuple[bool, str]:
    state = False
    error_message = ""

    conn = DatabaseClient(config=dbconf, logger=logger)
    try:
        routing_key: str = body["_routing_key"]

        if routing_key.endswith(".subtask.approve"):
            approval_type = "approve"
        elif routing_key.endswith(".subtask.disapprove"):
            approval_type = "disapprove"
        else:
            return False, f"Unexpected routing key '{routing_key}' for task approval"

        _ = body["state"]

        approval_revoked = body.get("revoke", False) or body.get("revoked", False)

        if not approval_revoked:
            _first, *_lines = [
                x
                for x in base64.b64decode(body["base64_message"])
                .decode("utf-8")
                .split("\n")
                if len(x) > 0
            ]
            _date, _name = [x.strip() for x in _first.split("::") if len(x) > 0]
            _date = datetime.strptime(_date, "%Y-%b-%d %H:%M:%S")
            approval_name = _name.split(" ")[-1]
            approval_date = set_datetime_timezone_to_utc(_date)
            approval_message = "\n".join((x for x in _lines))
        else:
            approval_name = body["girar_user"]
            approval_date = set_datetime_timezone_to_utc(
                datetime.fromtimestamp(float(body["_timestamp"]))
            )
            approval_message = ""

        task_approval = {
            "task_id": int(body["taskid"]),
            "subtask_id": int(body["subtaskid"]),
            "tapp_type": approval_type,
            "tapp_revoked": int(approval_revoked),
            "tapp_date": approval_date,
            "tapp_name": approval_name,
            "tapp_message": approval_message,
        }

        conn.execute("INSERT INTO TaskApprovals (*) VALUES", [task_approval])
        state = True
    except Exception as error:
        logger.error(f"{error} exception occured while saving task approval to DB")
        error_message = f"{error} exception occured while saving task approval to DB"
    finally:
        conn.disconnect()

    return state, error_message
