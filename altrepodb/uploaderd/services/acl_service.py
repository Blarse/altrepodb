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
from setproctitle import setproctitle

from ..service import ServiceBase, Work, mpEvent, WorkQueue, worker_sentinel
from ..base import NotifierMessageType, NotifierMessageSeverity
from altrepodb.database import DatabaseConfig, DatabaseClient

NAME = "altrepodb.acl_loader"
ROUTING_KEY_PATTERN = "acl."

logger = logging.getLogger(NAME)


class AclLoaderService(ServiceBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker = acl_loader_worker
        self.logger = logger
        self.routing_key_pattren = ""

    def load_config(self):
        super().load_config()

        self.routing_key_pattren = self.config.get("routing_key", ROUTING_KEY_PATTERN)
        self.publish_on_done = self.config.get("publish_on_done", False)
        self.requeue_on_reject = self.config.get("requeue_on_reject", False)
        self.max_redeliver_count = self.config.get("max_redeliver_count", 0)

    def on_message(self, method, properties, body_json):
        if not method.routing_key.startswith(self.routing_key_pattren):  # type: ignore
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
            self.logger.error(f"Failed to decode JSON payload: {error}")
            self.amqp.reject_message(method.delivery_tag, requeue=False)
            return

        logger.debug(f"Received message with payload: {body}")

        self.workers_todo_queue.put(
            Work(
                status="new",
                method=method,
                properties=properties,
                body_json=body_json,
            )
        )

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


def acl_loader_worker(
    stop_event: mpEvent,
    todo_queue: WorkQueue,
    done_queue: WorkQueue,
    dbconf: DatabaseConfig,
    config: dict[str, Any],
):
    setproctitle("repocop_loader_worker")
    conn = DatabaseClient(config=dbconf, logger=logger)

    while not stop_event.is_set():
        try:
            work = todo_queue.get()
            # exit if 'terminate' work received
            if work.status == worker_sentinel.status:
                return
        except KeyboardInterrupt:
            return

        work.status = "failed"

        error_message = ""
        state = False

        try:
            body = json.loads(work.body_json)

            acl = {
                "acl_date": datetime.datetime.fromtimestamp(float(body["_timestamp"])),
                "acl_for": body["target"],
                "acl_branch": body["repo"],
                "acl_list": body["new_owners"],
            }

            conn.execute("INSERT INTO Acl (*) VALUES", [acl])
            state = True
        except Exception as error:
            error_message = f"Failed to upload Acl data: {error}"
        finally:
            conn.disconnect()

        if error_message:
            logger.error(error_message)

        if state:
            work.status = "done"
        else:
            work.reason = error_message

        done_queue.put(work)
