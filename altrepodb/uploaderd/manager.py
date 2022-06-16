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

import time
import logging
import queue
from multiprocessing import Queue

from .service import ServiceAction, ServiceState, Message
from .services.services import SERVICES
from .notifier import NotifierManager, NotifierMessageSeverity, NotifierMessageType
from altrepodb.settings import MANAGER_SERVICE_COMMAND_TIMEOUT

NAME = "altrepodb.uploaderd.manager"

logger = logging.getLogger(NAME)


class ServiceManagerError(Exception):
    pass


class ServiceManager:
    def __init__(self, name: str, config_path: str, notifier: NotifierManager) -> None:
        self.name = name
        self.config = config_path
        self.notifier = notifier
        self.service = None
        self.service_state = ServiceState.RESET
        self.qin = Queue()
        self.qout = Queue()

    def initialize(self):
        self.service_state = ServiceState.RESET
        try:
            self.service = SERVICES[self.name](
                self.name,
                self.config,
                self.qin,  # type: ignore
                self.qout,  # type: ignore
            )
        except KeyError:
            raise ServiceManagerError(f"Service {self.name} not found")

        self.service.start()
        logger.debug(f"Service {self.name} process started")

    def start(self):
        if self.service is None:
            self.initialize()

        self.service_init()
        time.sleep(1)
        self.get_service_state()
        if self.service_state != ServiceState.INITIALIZED:
            raise ServiceManagerError(
                f"Failed to initialize service {self.name} with {self.service_reason}"
            )
        self.service_start()
        self.get_service_state()
        if self.service_state != ServiceState.RUNNING:
            raise ServiceManagerError(
                f"Failed to start service {self.name} with {self.service_reason}"
            )

        logger.info(f"Service {self.name} started")

    def stop(self):
        if self.service_state in (ServiceState.INITIALIZED, ServiceState.RUNNING):
            self.service_stop()
        while True:
            self.get_service_state()
            if self.service_state not in (ServiceState.RUNNING, ServiceState.STOPPING):
                break
            time.sleep(1)
        self.service_kill()

    def restart(self):
        self.stop()
        self.start()

    def service_init(self):
        self.qin.put_nowait(Message(ServiceAction.INIT))

    def service_start(self):
        self.qin.put_nowait(Message(ServiceAction.START))

    def service_stop(self):
        self.qin.put_nowait(Message(ServiceAction.STOP))

    def service_kill(self):
        if self.service is not None:
            self.qin.put_nowait(Message(ServiceAction.KILL))
            while True:
                self.get_service_state()
                if self.service_state in (
                    ServiceState.RESET,
                    ServiceState.FAILED,
                    ServiceState.DEAD,
                ):
                    break
                time.sleep(1)
            try:
                # self.service.terminate()
                self.service.kill()
                logger.info(f"Service {self.name} terminated")
            except AttributeError:
                pass
        self.service = None
        self.service_state = ServiceState.DEAD

    def get_service_state(self):
        if self.service_state in (ServiceState.DEAD, ServiceState.FAILED):
            return

        self._process_qout()

        self.service_state = ServiceState.UNKNOWN
        self.service_reason = ""

        try:
            self.qin.put_nowait(Message(ServiceAction.GET_STATE))
            resp: Message = self.qout.get(True, MANAGER_SERVICE_COMMAND_TIMEOUT)
            if resp.msg == ServiceAction.GET_STATE:
                self.service_state = resp.payload
                self.service_reason = resp.reason
        except (queue.Full, queue.Empty):
            self.service_state = ServiceState.FAILED
            self.service_reason = "timeout"
        logger.debug(
            f"Service {self.name} state: {self.service_state}, reason: {self.service_reason}"
        )

    def _process_qout(self):
        while True:
            try:
                resp: Message = self.qout.get_nowait()
            except queue.Empty:
                # all messages are consumed
                break

            try:
                if resp.reason == "notify":
                    self.notifier.send_message(
                        subject=self.name,
                        severity=resp.payload["severity"],
                        type=resp.payload["type"],
                        message=resp.payload["reason"],
                        payload=resp.payload["work_body"],
                    )
                else:
                    logger.warning(f"Service {self.name} reported: {resp.reason}")
                    self.notifier.send_message(
                        subject=self.name,
                        severity=NotifierMessageSeverity.WARNING,
                        type=NotifierMessageType.SERVICE_ERROR,
                        message=resp.reason,
                        payload=b"{}",
                    )
            except (KeyError, TypeError):
                # FIXME: ignoring inconsistent messages
                continue
