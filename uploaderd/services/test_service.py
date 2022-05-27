import json
import logging
import time
from datetime import datetime
from multiprocessing import Queue
from typing import Any

from altrepodb.utils import cvt_datetime_local_to_utc
from altrepodb.task.processor import TaskProcessor, TaskProcessorConfig
from ..logger import get_logger
from ..service import ServiceBase, Work
from altrepodb.task.exceptions import TaskLoaderProcessingError, TaskLoaderError
from altrepodb.database import DatabaseClient, DatabaseConfig

MAX_REDELIVER = 4

class TestService(ServiceBase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker = test_worker

    def load_config(self):
        config = super().load_config()
        return config

    def on_message(self, method, properties, body_json):

        headers = properties.headers
        if headers and headers.get('x-delivery-count', 0) >= MAX_REDELIVER:
            self.logger.info("Reject redelivered message")
            self.amqp.reject_message(method.delivery_tag, requeue=False)
            return

        self.logger.debug(f"AMQP message: {body_json}")
        self.workers_todo_queue.put(
            Work(
                status="new",
                method=method,
                properties=properties,
                body_json=body_json,
            )
        )

    def on_done(self, work):
        if self.amqp._closing:
            return

        if work.status == "done":
            self.amqp.ack_message(work.method.delivery_tag)
        else:
            self.amqp.reject_message(work.method.delivery_tag, requeue=False)

def test_worker(
    stop_event,
    todo_queue,
    done_queue,
    dbconf: DatabaseConfig,
):
    logger = get_logger("task_loader_worker")

    while not stop_event.is_set():
        try:
            task = todo_queue.get()
        except KeyboardInterrupt:
            return

        task.status = "failed"

        try:
            body = json.loads(task.body_json)
        except json.JSONDecodeError:
            logger.error("Failed to get message payload JSON")

        time.sleep(4)
        task.status = "done"

        done_queue.put(task)
