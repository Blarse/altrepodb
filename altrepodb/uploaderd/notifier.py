import logging
import threading
import queue
import time
import json
import pika

from typing import Any
from queue import Queue

from .amqp import AMQPConfig, SimplePublisher
from .base import NotifierMessageSeverity, NotifierMessageType, NotifierMessage

NAME = "altrepodb.notifier"

NOTIFIER_QUEUE_SIZE = 1000

logger = logging.getLogger(NAME)


class NotifierManager:
    def __init__(self, config: dict[str, Any]):
        self.queue = Queue(maxsize=NOTIFIER_QUEUE_SIZE)
        self.config = config
        self.notifier: NotifierService
        self.stop_event = threading.Event()

    def start(self):
        self.stop_event.clear()
        self.notifier = NotifierService(self.config, self.queue, self.stop_event)
        self.notifier.start()

    def stop(self):
        self.stop_event.set()
        self.notifier.join()

    def restart(self):
        self.stop()
        self.start()

    def send_message(
        self,
        subject: str,
        severity: NotifierMessageSeverity,
        type: NotifierMessageType,
        message: str,
        payload: Any = None,
    ):
        _message = NotifierMessage(
            subject=subject,
            severity=severity,
            type=type,
            message=message,
            payload=payload,
            timestamp=time.time(),
        )

        if not self.notifier.is_alive():
            self.restart()

        try:
            self.queue.put_nowait(_message)
        except queue.Full:
            logger.error(f"Notifier queue is full. Message not sent: {_message}")
            self.restart()


class NotifierService(threading.Thread):
    def __init__(
        self,
        config: dict[str, Any],
        queue: Queue,
        stop_event: threading.Event,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.config = config

        self.amqpconf: AMQPConfig
        self.load_config()
        self.amqp = SimplePublisher(self.amqpconf)

        self.queue = queue

        self.stop_event = stop_event

    def load_config(self):
        self.amqpconf = AMQPConfig(**self.config.get("amqp", {}))

    def run(self):
        amqp_properties = pika.spec.BasicProperties(
            content_type="application/json",
            delivery_mode=pika.DeliveryMode.Persistent.value,
        )

        while not self.stop_event.is_set():
            try:
                message = self.queue.get_nowait()
                logger.warning(f"New msg: {message}")
            except queue.Empty:
                time.sleep(1)
                continue

            try:
                routing_key = message.type.name + "." + message.severity.name
                routing_key = routing_key.lower()
                self.amqp.publish(
                    routing_key=routing_key,
                    body=json.dumps(message.to_dict(), default=str),
                    properties=amqp_properties,
                )
            except (pika.exceptions.NackError, pika.exceptions.UnroutableError) as exc:
                logger.error(f"Failed to publish message : {exc}")

        self.amqp.stop()
