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
import time
import pika
import queue
import signal
import logging
import multiprocessing as mp
from multiprocessing.synchronize import Event as EventClass
from setproctitle import setproctitle

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pika import spec as pika_spec
from pika.exceptions import AMQPError
from multiprocessing.context import SpawnProcess
from typing import Protocol, TypeVar, Generic, Any

from altrepodb.database import DatabaseConfig
from .amqp import AMQPConfig, BlockingAMQPClient
from .base import ServiceAction, ServiceState, Message
from .exceptions import (
    ServiceError,
    # ServiceUnexpectedMessage,
    ServiceLoadConfigError,
    # ServiceFailMessage,
)


NAME = "altrepodb.uploaderd.service"
WORKER_STOP_TIMEOUT = 60
IDLE_LOOP_SLEEP = 1.0
MAX_IDLE_LOOP_SLEEP = 10.0
AMQP_BATCH_SIZE = 1
MAX_AMQP_BATCH_SIZE = 100

logger = logging.getLogger(NAME)


@dataclass
class Work:
    status: str  # custom status string
    method: pika_spec.Basic.Deliver
    properties: pika_spec.BasicProperties
    body_json: bytes
    reason: str = ""


worker_sentinel = Work("terminate", None, None, None)  # type: ignore


T = TypeVar("T")


class TypedQueue(Generic[T]):
    def get(self) -> T:
        ...

    def get_nowait(self) -> T:
        ...

    def put(self, m: T) -> None:
        ...

    def put_nowait(self, m: T) -> None:
        ...


mpEvent = EventClass
WorkQueue = TypedQueue[Work]
MessageQueue = TypedQueue[Message]


class Worker(Protocol):
    """Service worker function protocol."""

    def __call__(
        self,
        stop_event: mpEvent,
        todo_queue: WorkQueue,
        done_queue: WorkQueue,
        dbconf: DatabaseConfig,
        config: dict[str, Any],
    ) -> None:
        pass


class ServiceBase(mp.Process, ABC):
    def __init__(self, name: str, config: str, qin: MessageQueue, qout: MessageQueue):
        super(ServiceBase, self).__init__()
        self.name = name
        self.config_path = config

        self.qin = qin
        self.qout = qout

        self.state = ServiceState.RESET
        self.reason = ""

        self.workers_count = 1
        self.workers: list[SpawnProcess] = []

        self._ctx = mp.get_context("spawn")
        self.workers_stop_event = self._ctx.Event()
        self.workers_todo_queue = self._ctx.Queue()
        self.workers_done_queue = self._ctx.Queue()

        self.amqp: BlockingAMQPClient
        self.dbconf: DatabaseConfig
        self.amqpconf: AMQPConfig
        self.worker: Worker

        self.config: dict[str, Any] = {}

        self.IDLE_LOOP_SLEEP: float = IDLE_LOOP_SLEEP

        self.routing_key: str
        self.publish_on_done: bool
        self.requeue_on_reject: bool
        self.max_redeliver_count: int
        # override inherited 'SIGTERM' handler
        signal.signal(signal.SIGTERM, self.service_terminate)

    def __repr__(self):
        return f"Service(name='{self.name}', config='{self.config_path}')"

    def service_terminate(self, signum, frame):
        logger.warning(f"{self.name} received SIGTERM")
        self.service_stop()
        raise SystemExit(0)

    def load_dbconf(self, section_db):
        self.dbconf = DatabaseConfig()
        self.dbconf.host = section_db.get("host", self.dbconf.host)
        self.dbconf.port = section_db.get("port", self.dbconf.port)
        self.dbconf.name = section_db.get("dbname", self.dbconf.name)
        self.dbconf.user = section_db.get("user", self.dbconf.user)
        self.dbconf.password = section_db.get("password", self.dbconf.password)

    def load_amqpconf(self, section_amqp):
        self.amqpconf = AMQPConfig()
        self.amqpconf.host = section_amqp.get("host", self.amqpconf.host)
        self.amqpconf.port = section_amqp.get("port", self.amqpconf.port)
        self.amqpconf.vhost = section_amqp.get("vhost", self.amqpconf.vhost)
        self.amqpconf.queue = section_amqp.get("queue", self.amqpconf.queue)
        self.amqpconf.exchange = section_amqp.get("exchange", self.amqpconf.exchange)
        self.amqpconf.username = section_amqp.get("username", self.amqpconf.username)
        self.amqpconf.password = section_amqp.get("password", self.amqpconf.password)
        self.amqpconf.cacert = section_amqp.get("cacert", self.amqpconf.cacert)
        self.amqpconf.key = section_amqp.get("key", self.amqpconf.key)
        self.amqpconf.cert = section_amqp.get("cert", self.amqpconf.cert)

    @abstractmethod
    def on_message(
        self,
        method: pika_spec.Basic.Deliver,
        properties: pika.BasicProperties,
        body_json: bytes,
    ):
        return

    @abstractmethod
    def on_done(self, done: Work):
        return

    @abstractmethod
    def load_config(self):
        try:
            with open(self.config_path, "r") as config_file:
                config = json.load(config_file)
        except json.JSONDecodeError as error:
            logger.error(f"Failed to parse {self.config_path}: {error}")
            raise ServiceLoadConfigError(f"Failed to parse {self.config_path}: {error}")
        except OSError as error:
            logger.error(f"Failed to open {self.config_path}: {error}")
            raise ServiceLoadConfigError(f"Failed to open {self.config_path}: {error}")

        if "database" in config:
            self.load_dbconf(config["database"])
        else:
            logger.error("Service config missing database section")
            raise ServiceLoadConfigError("Service config missing database section")

        if "amqp" in config:
            self.load_amqpconf(config["amqp"])
        else:
            raise ServiceLoadConfigError("Service config missing amqp section")

        self.workers_count = config.get("workers_count", self.workers_count)

        logger.debug(
            "Service config:\n"
            f"DB: {self.dbconf.name}@{self.dbconf.host}\n"
            f"AMQP: {self.amqpconf.host}:{self.amqpconf.port}, "
            f"vhost: {self.amqpconf.vhost}, exchange: {self.amqpconf.exchange}"
        )

        try:
            idle_loop_sleep = float(config.get("idle_loop_sleep"))
            if idle_loop_sleep < 0.1 or idle_loop_sleep > MAX_IDLE_LOOP_SLEEP:
                raise ServiceLoadConfigError(
                    f"Invalid idle loop sleep time value: {idle_loop_sleep}"
                    f", allowed range [0.1..{MAX_AMQP_BATCH_SIZE}]s"
                )
            self.IDLE_LOOP_SLEEP = idle_loop_sleep
        except (ValueError, TypeError):
            logger.warning(
                "Failed to parse idle loop sleep time from configuration. Use default"
            )

        self.config = config

    def report(self, reason: str, payload: Any = None):
        try:
            self.qout.put(
                Message(msg=ServiceAction.REPORT, reason=reason, payload=payload)
            )
        except queue.Full:
            logger.error("Service qout is full")
            pass

    def _process_state(self, command: int):
        if self.state == ServiceState.RESET:
            if command == ServiceAction.INIT:
                self.service_init()
        elif self.state == ServiceState.INITIALIZED:
            if command == ServiceAction.START:
                self.service_start()
            elif command == ServiceAction.STOP:
                self.service_stop()
        elif self.state == ServiceState.RUNNING:
            self._check_workers()
            self._process_amqp_message()
            self._process_workers_result()

            if command == ServiceAction.STOP:
                self.service_stop()
            elif command == ServiceAction.KILL:
                self.service_kill()
        elif self.state == ServiceState.STOPPED:
            if command == ServiceAction.START:
                self.service_start()
            elif command == ServiceAction.KILL:
                self.service_kill()
        elif self.state == ServiceState.STOPPING:
            self.service_stopped()
        elif self.state == ServiceState.FAILED:
            pass
        elif self.state == ServiceState.DEAD:
            pass

    def _process_amqp_message(self):
        message = self.amqp.get_message()
        if message is None:
            return
        self.on_message(
            method=message.method,
            properties=message.properties,
            body_json=message.body_json,
        )

    def _process_workers_result(self):
        if not self.workers_stop_event.is_set():
            try:
                self.on_done(self.workers_done_queue.get_nowait())
            except queue.Empty:
                pass

    def run(self):
        setproctitle(self.name)
        while True:
            command = ServiceAction.UNKNOWN
            try:
                message: Message = self.qin.get_nowait()
                command = message.msg
                logger.debug(f"Service {self.name} received: {command}")
                logger.debug(f"Service {self.name} state: {self.state.name}")

                if command == ServiceAction.GET_STATE:
                    try:
                        self.qout.put(
                            Message(
                                msg=ServiceAction.GET_STATE,
                                reason="service state",
                                payload=self.state,
                            )
                        )
                    except queue.Full:
                        logger.error("Service qout is full")
            except queue.Empty:
                pass

            try:
                self._process_state(command)
            except Exception as error:
                self.service_fail(repr(error))
                # return
            except KeyboardInterrupt:
                logger.info(f"Service {self.name} interrupted")
                self.service_kill()
                return
            # XXX: slow down idle loop to reduce CPU utilization
            time.sleep(self.IDLE_LOOP_SLEEP)

    def service_init(self):
        logger.info(f"Initialize service {self.name}")
        try:
            self.load_config()
        except ServiceError as error:
            self.service_fail(repr(error))
            return

        # 2. start workers
        logger.debug(f"Starting workers({self.workers_count})")

        try:
            for _ in range(self.workers_count):
                worker = self._ctx.Process(
                    target=self.worker,
                    args=(
                        self.workers_stop_event,
                        self.workers_todo_queue,
                        self.workers_done_queue,
                        self.dbconf,
                        self.config,
                    ),
                )
                worker.start()
                self.workers.append(worker)
        except mp.ProcessError as error:
            self.service_fail(repr(error))
            return

        # 3. create amqp connection and open channel
        self.amqp = BlockingAMQPClient(self.amqpconf)
        try:
            self.amqp.ensure_channel()
        except AMQPError as error:
            self.service_fail(repr(error))
            return

        self.state = ServiceState.INITIALIZED

    def service_reset(self):
        logger.info(f"Reset service {self.name}")
        self.state = ServiceState.RESET

    def service_start(self):
        logger.info(f"Start service {self.name}")
        self.state = ServiceState.RUNNING

    def service_stop(self):
        logger.info(f"Stop service {self.name}")

        # send 'stop' event to all workers and wait until all of them are terminated
        self.workers_stop_event.set()
        # put 'exit' work messages for all workers
        for _ in self.workers:
            self.workers_todo_queue.put_nowait(worker_sentinel)

        timer = 0
        timed_out = False
        while True:
            logger.debug("Waiting for worker process is down")
            if not any([w.is_alive() for w in self.workers]):
                break
            time.sleep(1)
            timer += 1
            if timer > WORKER_STOP_TIMEOUT:
                timed_out = True
                break

        if not timed_out:
            self.state = ServiceState.STOPPING
        else:
            self.service_fail("Worker stop is timed out")

    def service_stopped(self):
        logger.info(f"Service {self.name} stopped")
        self.state = ServiceState.STOPPED

    def service_fail(self, reason: str):
        self.reason = reason
        logger.info(f"Service {self.name} failed due to {self.reason}")
        self.kill_workers()
        self.state = ServiceState.FAILED
        self.report(reason=self.reason, payload=self.state)

    def service_kill(self):
        logger.info(f"Killing service {self.name}")
        self.kill_workers()
        self.state = ServiceState.DEAD

    def _check_workers(self):
        if not all(worker.is_alive() for worker in self.workers):
            self.service_fail("dead workers")

    def kill_workers(self):
        logger.info(f"Killing all workers of {self.name}")
        # send 'stop' event to all workers and wait until all of them are terminated
        self.workers_stop_event.set()
        # empty worker's queues
        while True:
            try:
                _ = self.workers_todo_queue.get_nowait()
            except queue.Empty:
                break
        while True:
            try:
                _ = self.workers_done_queue.get_nowait()
            except queue.Empty:
                break
        # terminate workers process
        for worker in self.workers[:]:
            worker.terminate()
            self.workers.remove(worker)


class BatchServiceBase(ServiceBase):
    def __init__(self, name: str, config: str, qin: MessageQueue, qout: MessageQueue):
        super().__init__(name, config, qin, qout)
        self.BATCH_SIZE = AMQP_BATCH_SIZE

    def load_config(self):
        super().load_config()

        try:
            batch_size = int(self.config.get("amqp_batch_size"))  # type: ignore
            if batch_size < 1 or batch_size > MAX_AMQP_BATCH_SIZE:
                raise ServiceLoadConfigError(
                    f"Invalid AMQP batch size: {batch_size}"
                    f", allowed range [1..{MAX_AMQP_BATCH_SIZE}]"
                )
            self.BATCH_SIZE = batch_size
        except (ValueError, TypeError):
            logger.warning(
                "Failed to parse AMQP batch size from configuration. Use default"
            )

    def _process_amqp_message(self):
        batch_count = 0
        while True:
            message = self.amqp.get_message()
            if message is None:
                return
            self.on_message(
                method=message.method,
                properties=message.properties,
                body_json=message.body_json,
            )
            batch_count += 1
            if batch_count >= self.BATCH_SIZE:
                return

    def _process_workers_result(self):
        if not self.workers_stop_event.is_set():
            while True:
                try:
                    self.on_done(self.workers_done_queue.get_nowait())
                except queue.Empty:
                    return
