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
from pathlib import Path
from datetime import datetime

from altrepodb.repo.processor import RepoProcessor, RepoProcessorConfig
from ..service import ServiceBase, Work, mpEvent, WorkQueue, worker_sentinel
from ..base import NotifierMessageType, NotifierMessageSeverity
from altrepodb.database import DatabaseConfig

NAME = "altrepodb.repo_loader"
ROUTING_KEY = "repo.load"
MAX_REDELIVER = 3
REPO_DIR = "/archive/repo"
REPO_THREADS_COUNT = 4

logger = logging.getLogger(NAME)


class RepoServiceError(Exception):
    pass


class RepoLoaderService(ServiceBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker = repo_loader_worker
        self.logger = logger

    def load_config(self):
        super().load_config()
        if "routing_key" not in self.config:
            self.config["routing_key"] = ROUTING_KEY

        if "repo_dir" not in self.config:
            self.config["repo_dir"] = REPO_DIR

    def on_message(self, method, properties, body_json):
        if method.routing_key != self.config["routing_key"]:
            self.logger.critical(f"Unexpected routing key : {method.routing_key}")
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

        for item in ("branch", "date"):
            if item not in body:
                logger.error(f"item '{item}' not found in message payload")

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
            self.amqp.publish(work.method.routing_key, work.body_json, work.properties)
        else:
            # requeue message if load failed
            self.amqp.reject_message(work.method.delivery_tag, requeue=True)
            self.report(
                reason="notify",
                payload={
                    "reason": work.reason,
                    "type": NotifierMessageType.SERVICE_WORKER_ERROR,
                    "severity": NotifierMessageSeverity.CRITICAL,
                    "work_body": work.body_json,
                },
            )


def repo_loader_worker(
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

        work.status = "failed"

        error_message = ""
        state = False

        try:
            body = json.loads(work.body_json)

            branch = body["branch"]
            date_ = body["date"].split("-")
            repo_date = datetime.strptime(body["date"], "%Y-%m-%d")

            # check if repository path is provided in message payload
            if "repo_path" in body:
                repo_path = Path(body["repo_path"])
            else:
                repo_path = Path(config["repo_dir"]).joinpath(
                    branch, "date", f"{date_[0]}/{date_[1]}/{date_[2]}"
                )

            if not repo_path.is_dir():
                error_message = f"Invalid repository path: {str(repo_path)}"
                raise RepoServiceError

            rpconfig = RepoProcessorConfig(
                name=branch,
                path=repo_path,
                date=repo_date,
                workers=config.get("threads_count", REPO_THREADS_COUNT),
                dbconfig=dbconf,
                logger=logger,
                tag="uploaderd",
            )
            rp = RepoProcessor(rpconfig)
            logger.info(f"Start loading repository {branch} on {body['date']}")
            rp.run()
            logger.info("Repository data uploaded successfully")
            state = True
        except RepoServiceError:
            # error message is set above
            pass
        except Exception as error:
            error_message = f"Failed to upload repository data: {error}"

        if error_message:
            logger.error(error_message)

        if state:
            work.status = "done"
        else:
            work.reason = error_message

        done_queue.put(work)
