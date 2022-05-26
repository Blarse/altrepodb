import queue
from typing import Type

from .service import ServiceBase, ServiceAction, ServiceState, Message

from services.test_service import TestService
from services.task_service import TaskLoaderService


SERVICES: dict[str, Type[ServiceBase]] = {
    "test_service" : TestService,
    "task_loader" : TaskLoaderService,
    # "bug_loader" : BugLoader
}


class ServiceManager:
    def __init__(self, name, config_path, debug=False):
        self.name = name
        self.config_path = config_path
        self.debug = debug

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
            self.qin,
            self.qout,
            self.debug
        )

        self.service.start()

    def stop(self):
        self.service_stop()
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
        self.service_expected_state = ServiceState.STOPPED

    def service_kill(self):
        self.qin.put_nowait(Message(ServiceAction.KILL))
        self.service_expected_state = ServiceState.UNKNOWN

    def service_get_state(self):
        self.service_prev_state = self.service_state
        self.service_state = ServiceState.UNKNOWN
        try:
            self.qin.put_nowait(Message(ServiceAction.GET_STATE))
            resp = self.qout.get(True, 10)
            self.service_state = resp.msg
            self.service_reason = resp.reason
        except (queue.Full, queue.Empty):
            self.service_state = ServiceState.FAILED
            self.service_reason = "timeout"
