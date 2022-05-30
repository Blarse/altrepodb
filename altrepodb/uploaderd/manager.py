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


class ServiceManager:
    def __init__(self, name: str, config_path: str):
        self.name = name
        self.config_path = config_path

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

        self.service = SERVICES[self.name](
            self.name,
            self.config_path,
            self.qin,  # type: ignore
            self.qout,  # type: ignore
        )

        self.service.start()

    def stop(self):
        self.service_stop()
        while (
            self.service_state != ServiceState.STOPPED
            or self.service_state != ServiceState.FAILED
        ):
            self.service_get_state()
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
