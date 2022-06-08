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
import queue

from .service import ServiceAction, ServiceState, Message
from .services.services import SERVICES
from .notifier import NotifierManager


class ServiceManagerError(Exception):
    pass


class ServiceManager:
    def __init__(self, name: str, config_path: str, notifier: NotifierManager):
        self.name = name
        self.config_path = config_path
        self.notifier = notifier

        self.service = None

        self.service_state = ServiceState.RESET
        self.service_expected_state = ServiceState.RESET
        self.service_prev_state = ServiceState.UNKNOWN

        self.service_reason = ""

        self.qin = queue.Queue()
        self.qout = queue.Queue()

    def start(self):
        self.service_state = ServiceState.RESET
        self.service_expected_state = ServiceState.RESET
        self.service_prev_state = ServiceState.UNKNOWN
        self.service_reason = ""

        try:
            self.service = SERVICES[self.name](
                self.name,
                self.config_path,
                self.qin,  # type: ignore
                self.qout,  # type: ignore
            )
        except KeyError:
            raise ServiceManagerError(f"Service {self.name} not found")

        self.service.start()

    def stop(self):
        if self.service_state in (
            ServiceState.INITIALIZED,
            ServiceState.RUNNING
        ):
            self.service_stop()
        while True:
            self.service_get_state()
            if self.service_state not in (
                ServiceState.RUNNING,
                ServiceState.STOPPING
            ):
                break
            time.sleep(1)
        self.service_kill()
        self.service_state = ServiceState.DEAD

    def restart(self):
        self.stop()
        self.start()

    def service_init(self):
        self.qin.put_nowait(Message(ServiceAction.INIT))
        self.service_expected_state = ServiceState.INITIALIZED

    def service_start(self):
        self.qin.put_nowait(Message(ServiceAction.START))
        self.service_expected_state = ServiceState.RUNNING

    def service_stop(self):
        self.qin.put_nowait(Message(ServiceAction.STOP))
        # FIXME: expect both STOPPING and STOPPED
        self.service_expected_state = ServiceState.STOPPING

    def service_kill(self):
        self.qin.put_nowait(Message(ServiceAction.KILL))
        self.service_expected_state = ServiceState.UNKNOWN

    def service_get_state(self):

        self._process_qout()

        self.service_prev_state = self.service_state
        self.service_state = ServiceState.UNKNOWN
        self.service_reason = ""
        try:
            self.qin.put_nowait(Message(ServiceAction.GET_STATE))
            resp = self.qout.get(True, 10)
            self.service_state = resp.msg
            self.service_reason = resp.reason
        except (queue.Full, queue.Empty):
            self.service_state = ServiceState.FAILED
            self.service_reason = "timeout"

    def _process_qout(self):
        while True:
            try:
                resp = self.qout.get_nowait()
            except queue.Empty:
                # all messages are consumed
                break

            try:
                self.notifier.send_message(
                    subject=self.name,
                    severity=resp.payload["severity"],
                    type=resp.payload["type"],
                    message=resp.payload["reason"],
                    payload=resp.payload["work_body"],
                )
            except KeyError:
                # FIXME: ignoring inconsistent messages
                continue
