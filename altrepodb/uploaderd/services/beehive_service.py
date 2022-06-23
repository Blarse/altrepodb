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
from typing import Any
from setproctitle import setproctitle

from altrepodb.beehive import (
    Beehive,
    BeehiveConfig,
    BeehiveLoadError,
    Endpoint,
    EndpointType,
)
from ..service import ServiceBase, Work, mpEvent, WorkQueue, worker_sentinel
from ..base import NotifierMessageType, NotifierMessageSeverity
from altrepodb.database import DatabaseConfig

NAME = "altrepodb.beehive_loader"
ROUTING_KEY = "beehive.load"
BEEHIVE_BASE_URL = "https://git.altlinux.org/beehive"
BEEHIVE_BRANCHES = (
    "Sisyphus",
    "p10",
    "p9",
)
BEEHIVE_ARCHS = ("i586", "x86_64")
BEEHIVE_ENDPOINTS = (
    Endpoint("latest_dir_mtime", EndpointType.DIR, "logs", "", "latest"),
    Endpoint("time_file_listing", EndpointType.FILE1, "logs", "latest/time.list", None),
    Endpoint("error_dir_listing", EndpointType.DIR, "logs", "latest/error", None),
    Endpoint("success_dir_listing", EndpointType.DIR, "logs", "latest/success", None),
    Endpoint(
        "ftbfs_since_file_listing", EndpointType.FILE2, "stats", "ftbfs-since", None
    ),
)
BEEHIVE_REQUEST_TIMEOUT = 30

logger = logging.getLogger(NAME)


class BeehiveLoaderService(ServiceBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker = beehive_loader_worker
        self.logger = logger

    def load_config(self):
        super().load_config()

        self.routing_key = self.config.get("routing_key", ROUTING_KEY)
        self.publish_on_done = self.config.get("publish_on_done", False)
        self.requeue_on_reject = self.config.get("requeue_on_reject", False)
        self.max_redeliver_count = self.config.get("max_redeliver_count", 0)

    def on_message(self, method, properties, body_json):
        if method.routing_key != self.routing_key:
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
            # requeue message if beehive load failed
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


def beehive_loader_worker(
    stop_event: mpEvent,
    todo_queue: WorkQueue,
    done_queue: WorkQueue,
    dbconf: DatabaseConfig,
    config: dict[str, Any],
):
    setproctitle("beehive_loader_worker")
    bpconf = BeehiveConfig(
        base_url=config.get("base_url", BEEHIVE_BASE_URL),
        archs=tuple(config.get("archs", BEEHIVE_ARCHS)),
        branches=tuple(config.get("branches", BEEHIVE_BRANCHES)),
        timeout=config.get("timeout", BEEHIVE_REQUEST_TIMEOUT),
        logger=logger,
        dbconfig=dbconf,
        endpoints=BEEHIVE_ENDPOINTS,
    )

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
            bp = Beehive(bpconf)
            logger.info("Start loading data from Beehive")
            bp.run()
            logger.info("Beehive data uploaded successfully")
            state = True
        except (BeehiveLoadError, Exception) as error:
            error_message = f"Failed to upload Beehive data: {error}"

        if error_message:
            logger.error(error_message)

        if state:
            work.status = "done"
        else:
            work.reason = error_message

        done_queue.put(work)
