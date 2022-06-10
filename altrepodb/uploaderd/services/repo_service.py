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
from ..service import (
    ServiceBase,
    ServiceError,
    Work,
    mpEvent,
    WorkQueue,
    worker_sentinel,
)
from ..base import NotifierMessageType, NotifierMessageSeverity
from altrepodb.database import DatabaseConfig

NAME = "altrepodb.repo_loader"
ROUTING_KEY = "repo.load"
REPO_THREADS_COUNT = 4

logger = logging.getLogger(NAME)


class RepoServiceError(Exception):
    pass


class RepoLoaderService(ServiceBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker = repo_loader_worker
        self.logger = logger

        self.repo_dirs: dict[str, str] = {}
        self.validate_date: bool = False

    def load_config(self):
        super().load_config()

        self.routing_key = self.config.get("routing_key", ROUTING_KEY)
        self.publish_on_done = self.config.get("publish_on_done", False)
        self.requeue_on_reject = self.config.get("requeue_on_reject", False)
        self.max_redeliver_count = self.config.get("max_redeliver_count", 0)
        self.validate_date = self.config.get("validate_date", False)

        try:
            self.repo_dirs = self.config["repo_dirs"]
        except KeyError:
            raise ServiceError(
                "No repository directories table found in configuration file"
            )

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

        body_is_valid = True

        for item in ("branch", "date"):
            if item not in body:
                body_is_valid = False
                logger.error(f"item '{item}' not found in message payload")

        if body_is_valid and (body["branch"] not in self.repo_dirs):
            body_is_valid = False
            logger.error(
                f"No repository directory is configured for branch {body['branch']}"
            )

        repo_date = None
        if body_is_valid:
            try:
                repo_date = datetime.strptime(body["date"], "%Y-%m-%d").date()
            except (TypeError, ValueError):
                body_is_valid = False
                self.logger.error("Repository date is not valid")

        if (
            body_is_valid
            and self.validate_date
            and repo_date != datetime.today().date()
        ):
            body_is_valid = False
            self.logger.error("Repository date is inconsistent")

        logger.debug(f"Received message with payload: {body}")

        if body_is_valid:
            body["repo_path"] = self.repo_dirs[body["branch"]]
            self.workers_todo_queue.put(
                Work(
                    status="new",
                    method=method,
                    properties=properties,
                    body_json=json.dumps(body).encode("utf-8"),
                )
            )
        else:
            self.logger.info("Reject inconsistent message")
            self.amqp.reject_message(method.delivery_tag, requeue=False)

    def on_done(self, work: Work):
        if work.status == "done":
            self.amqp.ack_message(work.method.delivery_tag)
            if self.publish_on_done:
                self.amqp.publish(
                    work.method.routing_key, work.body_json, work.properties
                )
        else:
            # requeue message if load failed
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

            repo_branch = body["branch"]
            repo_date = datetime.strptime(body["date"], "%Y-%m-%d")

            # check if repository path is provided in message payload
            if "repo_path" not in body:
                error_message = "Repository path is missing"
                raise RepoServiceError

            repo_path = Path(body["repo_path"])

            if not repo_path.is_dir():
                error_message = f"Invalid repository path: {str(repo_path)}"
                raise RepoServiceError

            rpconfig = RepoProcessorConfig(
                name=repo_branch,
                path=repo_path,
                date=repo_date,
                workers=config.get("threads_count", REPO_THREADS_COUNT),
                dbconfig=dbconf,
                logger=logger,
                tag="uploaderd",
            )
            rp = RepoProcessor(rpconfig)
            logger.info(f"Start loading repository {repo_branch} on {body['date']}")
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
