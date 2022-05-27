import logging
import threading
import multiprocessing as mp
import queue
import asyncio
import json
import pika

from queue import Queue
from multiprocessing.context import SpawnProcess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pika import spec as pika_spec
from typing import Protocol, TypeVar, Generic, Any

from altrepodb.database import DatabaseConfig
from .amqp import AMQPClient, AMQPConfig
from .base import ServiceAction, ServiceState, Message
from .exceptions import (
    ServiceError,
    # ServiceUnexpectedMessage,
    ServiceLoadConfigError,
    # ServiceFailMessage,
)


NAME = "altrepodb.uploaderd.service"

ACTION_ALLOWED_STATES = {
    ServiceAction.INIT: [ServiceState.RESET],
    ServiceAction.START: [ServiceState.INITIALIZED],
    ServiceAction.STOP: [ServiceState.INITIALIZED, ServiceState.RUNNING],
    ServiceAction.GET_STATE: [
        ServiceState.RESET,
        ServiceState.INITIALIZED,
        ServiceState.RUNNING,
        ServiceState.FAILED,
        ServiceState.STOPPING,
        ServiceState.STOPPED,
    ],
    ServiceAction.KILL: [ServiceState.FAILED, ServiceState.STOPPED],
}


@dataclass
class Work:
    status: str  # custom status string
    method: pika_spec.Basic.Deliver
    properties: pika_spec.BasicProperties
    body_json: bytes


T = TypeVar("T")


class TypedQueue(Generic[T]):
    def get(self) -> T:
        ...

    def put(self, m: T) -> None:
        ...


mpEvent = type(mp.Event)
WorkQueue = TypedQueue[Work]


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


class ServiceBase(threading.Thread, ABC):
    def __init__(
        self,
        name: str,
        config: str,
        qin: Queue,
        qout: Queue,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
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

        self.amqp: AMQPClient
        self.dbconf: DatabaseConfig
        self.amqpconf: AMQPConfig

        self.worker: Worker
        self.config: dict[str, Any] = {}

        self.logger = logging.getLogger(NAME)

    def run(self):
        self.logger.info(f"{self.name} started")

        self.loop = asyncio.new_event_loop()

        self.loop.create_task(self.main())
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            self.logger.error("Interrupted")

    async def main(self):
        try:
            while True:
                try:
                    resp = self.qin.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(1)
                    continue

                self.logger.debug(f"New message: {resp}")

                if self.state not in ACTION_ALLOWED_STATES[resp.msg]:
                    self.logger.warning("illegal state transition")
                    continue

                if resp.msg == ServiceAction.INIT:
                    await self.service_init()
                elif resp.msg == ServiceAction.START:
                    self.service_start()
                elif resp.msg == ServiceAction.STOP:
                    # await self.service_stop()
                    self.loop.create_task(self.service_stop())

                    self.state = ServiceState.STOPPING
                    self.logger.debug("stopping")
                elif resp.msg == ServiceAction.GET_STATE:
                    self.service_get_state()
                elif resp.msg == ServiceAction.KILL:
                    self.loop.stop()
                    return

        except KeyboardInterrupt as error:
            await self.service_stop()
            raise error

    async def service_init(self):
        # 1. parse and validate config
        try:
            self.load_config()
        except ServiceError as error:
            self.service_fail(repr(error))
            return

        # 2. start workers
        self.logger.debug(f"Starting workers({self.workers_count})")

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
        self.amqp = AMQPClient(self.logger, self.amqpconf, self.loop)

        self.amqp.start()

        try:
            await asyncio.wait_for(self.amqp.events["connection"].wait(), 10)
        except asyncio.TimeoutError:
            self.service_fail(self.amqp.reason)
            return

        try:
            await asyncio.wait_for(self.amqp.events["channel"].wait(), 10)
        except asyncio.TimeoutError:
            self.service_fail(self.amqp.reason)
            return

        self.state = ServiceState.INITIALIZED

    def service_start(self):
        self.amqp.start_consuming(self.on_message_wrapper)
        self.loop.create_task(self.worker_results_handler())
        self.state = ServiceState.RUNNING

    def service_fail(self, reason: str):
        self.state = ServiceState.FAILED
        self.reason = reason

        self.kill_workers()

        if self.amqp:
            self.amqp.stop()

    async def service_stop(self):
        if self.amqp:
            self.amqp.stop()

        await asyncio.wait_for(self.amqp.events["stop"].wait(), None)

        # send 'stop' event to all workers and wait until all of them are terminated
        self.workers_stop_event.set()

        while any([w.is_alive() for w in self.workers]):
            await asyncio.sleep(1)

        self.state = ServiceState.STOPPED

    async def worker_results_handler(self):
        while not self.workers_stop_event.is_set():
            try:
                self.on_done(self.workers_done_queue.get_nowait())
            except queue.Empty:
                await asyncio.sleep(1)
                continue

    def service_get_state(self):
        self.self_test()

        self.qout.put(Message(self.state, self.reason))

    def kill_workers(self):
        self.logger.debug("Killing workers")
        # FIXME: potential issue with workers pipes and subprocesses that may become malfunctional
        for worker in self.workers:
            # TODO: check if some processes ignores SIGTERM
            worker.terminate()
            # worker.kill()

    def self_test(self):
        if self.state == ServiceState.RUNNING:
            if not all(worker.is_alive() for worker in self.workers):
                self.service_fail("dead workers")
                return

            if not self.amqp._consuming:
                self.service_fail("amqp error")
                return

    def on_message_wrapper(self, channel, method, properties, body_json):
        try:
            self.on_message(method, properties, body_json)
        except Exception as error:
            self.logger.error(f"Exception in on_message: {error}")

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
    def load_config(self):
        try:
            with open(self.config_path, "r") as config_file:
                config = json.load(config_file)
        except json.JSONDecodeError as error:
            self.logger.error(f"Failed to parse {self.config_path}: {error}")
            raise ServiceLoadConfigError(f"Failed to parse {self.config_path}: {error}")
        except OSError as error:
            self.logger.error(f"Failed to open {self.config_path}: {error}")
            raise ServiceLoadConfigError(f"Failed to open {self.config_path}: {error}")

        if "database" in config:
            self.load_dbconf(config["database"])
        else:
            self.logger.error("Service config missing database section")
            raise ServiceLoadConfigError("Service config missing database section")

        if "amqp" in config:
            self.load_amqpconf(config["amqp"])
        else:
            raise ServiceLoadConfigError("Service config missing amqp section")

        self.workers_count = config.get("workers_count", self.workers_count)

        self.logger.debug(f"Service config:\n{self.dbconf}\n{self.amqpconf}")

        self.config = config

    @abstractmethod
    def on_done(self, done: WorkQueue):
        return

    def __repr__(self):
        return f"Service(name='{self.name}', config='{self.config_path}')"
