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
import datetime
from typing import Any
from collections import namedtuple
from setproctitle import setproctitle

from ..service import ServiceBase, Work, mpEvent, WorkQueue, worker_sentinel
from ..base import (
    NotifierMessageType,
    NotifierMessageSeverity,
    NotifierMessageReason,
    WorkStatus,
)
from altrepodb.database import DatabaseConfig, DatabaseClient
from altrepodb.utils import set_datetime_timezone_to_utc, cvt_datetime_local_to_utc

NAME = "altrepodb.bugzilla_loader"
ROUTING_KEY_PATTERN = "bugzilla."
RKEY_COMMENT_NEW = "comment.new"
RKEY_BUG_CHANGED_PREFIX = "bug.changed."

logger = logging.getLogger(NAME)


Bug = namedtuple(
    "Bug",
    [
        "bz_id",
        "bz_status",
        "bz_resolution",
        "bz_severity",
        "bz_product",
        "bz_component",
        "bz_assignee",
        "bz_reporter",
        "bz_summary",
        "bz_last_changed",
        "bz_assignee_full",
        "bz_reporter_full",
    ],
)


class BugzillaLoaderService(ServiceBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker = bugzilla_loader_worker
        self.logger = logger
        self.routing_key_pattern = ""

    def load_config(self):
        super().load_config()

        self.routing_key_pattern = self.config.get(
            "routing_key_pattern", ROUTING_KEY_PATTERN
        )
        self.publish_on_done = self.config.get("publish_on_done", False)
        self.requeue_on_reject = self.config.get("requeue_on_reject", False)
        self.max_redeliver_count = self.config.get("max_redeliver_count", 0)

    def on_message(self, method, properties, body_json):
        if not method.routing_key.startswith(self.routing_key_pattern):  # type: ignore
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
            self.logger.error(f"Failed to decode JSON payload: {repr(error)}")
            self.amqp.reject_message(method.delivery_tag, requeue=False)
            return

        logger.debug(f"Received message with payload: {body}")

        self.workers_todo_queue.put(
            Work(
                status=WorkStatus.NEW,
                method=method,
                properties=properties,
                body_json=body_json,
            )
        )

    def on_done(self, work: Work):
        if work.status == WorkStatus.DONE:
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
                reason=NotifierMessageReason.NOTIFY,
                payload={
                    "reason": work.reason,
                    "type": NotifierMessageType.SERVICE_WORKER_ERROR,
                    "severity": NotifierMessageSeverity.CRITICAL,
                    "work_body": work.body_json,
                },
            )


def bugzilla_loader_worker(
    stop_event: mpEvent,
    todo_queue: WorkQueue,
    done_queue: WorkQueue,
    dbconf: DatabaseConfig,
    config: dict[str, Any],
):
    setproctitle("bugzilla_loader_worker")
    conn = DatabaseClient(config=dbconf, logger=logger)

    while not stop_event.is_set():
        try:
            work = todo_queue.get()
            # exit if 'terminate' work received
            if work.status == worker_sentinel.status:
                return
        except KeyboardInterrupt:
            return

        body: dict[str, Any] = {}
        work.status = WorkStatus.FAILED

        try:
            body = json.loads(work.body_json)
        except json.JSONDecodeError:
            logger.error("Failed to get message payload JSON")
            work.reason = "Failed to get message payload JSON"
            done_queue.put(work)
            continue

        error_message = ""
        state = False

        routing_key = str(work.method.routing_key).replace(
            config["routing_key_pattern"], ""
        )

        try:
            last_changed = set_datetime_timezone_to_utc(
                datetime.datetime.fromisoformat(body["_meta"]["time"])
            )
            payload: dict[str, Any] = body["payload"]
            bug: dict[str, Any] = {}

            if routing_key == RKEY_COMMENT_NEW:
                bug = payload["comment"]["bug"]
            elif routing_key.startswith(RKEY_BUG_CHANGED_PREFIX):
                bug = payload["bug"]
            else:
                logger.debug(
                    f"Nothing to do with routing key '{work.method.routing_key}'"
                )
                state = True

            if not state:
                load_bug_to_database(conn, bug, last_changed)
                state = True
        except Exception as error:
            error_message = f"Failed to upload Bugzilla data: {repr(error)}"
        finally:
            conn.disconnect()

        if error_message:
            logger.error(error_message)

        if state:
            work.status = WorkStatus.DONE
        else:
            work.reason = error_message

        done_queue.put(work)


def load_bug_to_database(
    conn: DatabaseClient, bug: dict[str, Any], last_changed: datetime.datetime
):
    def get_nickname(email: str) -> str:
        return email.split("@")[0]

    payload = {
        "bz_id": int(bug["id"]),
        "bz_status": bug["status"]["label"],
        "bz_resolution": bug["resolution"],
        "bz_severity": bug["severity"],
        "bz_product": bug["product"]["name"],
        "bz_component": bug["component"]["name"],
        "bz_assignee": get_nickname(bug["assigned_to"]["login"]),
        "bz_reporter": get_nickname(bug["reporter"]["login"]),
        "bz_summary": bug["summary"],
        "bz_last_changed": last_changed,
        "bz_assignee_full": bug["assigned_to"]["login"],
        "bz_reporter_full": bug["reporter"]["login"],
    }

    # get last bug state from DB
    sql = """
SELECT
    argMax(
        (
            bz_id,
            bz_status,
            bz_resolution,
            bz_severity,
            bz_product,
            bz_component,
            bz_assignee,
            bz_reporter,
            bz_summary,
            bz_last_changed,
            bz_assignee_full,
            bz_reporter_full,
        ),
        ts
    )
FROM Bugzilla
WHERE bz_id = {bug_id}"""

    updated = False
    res = conn.execute(sql.format(bug_id=int(bug["id"])))

    # skip duplicated bug states from distinct Bugzilla AMQP messages
    if not res:
        updated = True
    else:
        bug_from_db = Bug(*res[0][0])._asdict()
        bug_from_db["bz_last_changed"] = cvt_datetime_local_to_utc(
            bug_from_db["bz_last_changed"]
        )
        if bug_from_db != payload:
            updated = True

    if updated:
        conn.execute("INSERT INTO Bugzilla (*) VALUES", [payload])
