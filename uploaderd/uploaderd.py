import sys
import json
import time
import logging
import systemd.daemon
from typing import Optional
from dataclasses import dataclass

from .base import ServiceState
from .manager import ServiceManager

NAME = "uploaderd"
DEFAULT_CONFIG_FILE = "/etc/uploaderd/config.json"
DEFAULT_SERVICE_CONF_DIR = "/etc/uploaderd/services.d/"
DEFAULT_BASE_TIMEOUT = 10


class UploaderDaemonError(Exception):
    pass


@dataclass
class UploaderDaemonConfig:
    config_file: str = DEFAULT_CONFIG_FILE
    services_config_dir: str = DEFAULT_SERVICE_CONF_DIR
    service_timeout: int = DEFAULT_BASE_TIMEOUT
    logger: Optional[logging.Logger] = None
    debug: bool = False


class UploaderDaemon:
    def __init__(self, config: UploaderDaemonConfig) -> None:
        self.config_file = config.config_file
        self.services_config_dir = config.services_config_dir
        self.timeout = config.service_timeout
        self.debug = config.debug

        if config.logger:
            self.logger = config.logger
        else:
            self.logger = logging.getLogger(NAME)

        if config.debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        self.managers: list[ServiceManager] = []

    def _populate_services(self) -> None:
        self.logger.debug(f"Reading config file: '{self.config_file}'")
        try:
            with open(self.config_file, "r") as config_file:
                config = json.load(config_file)
        except json.JSONDecodeError as error:
            self.logger.error(f"Failed to parse {self.config_file}: {error}")
            raise UploaderDaemonError
        except OSError as error:
            self.logger.error(f"Failed to open {self.config_file}: {error}")
            raise UploaderDaemonError

        if "services" in config:
            for service_entry in config["services"]:
                self.logger.debug(f"Loading {service_entry['name']} service")
                self.managers.append(
                    ServiceManager(
                        service_entry["name"],
                        self.services_config_dir + service_entry["config"],
                    )
                )
        else:
            self.logger.critical("No services configuration found")
            raise UploaderDaemonError

    def _services_loop(self) -> None:
        for sm in self.managers[:]:
            while True:
                sm.service_get_state()

                if sm.service_state != sm.service_expected_state:
                    if sm.service_expected_state == ServiceState.INITIALIZED:
                        self.logger.error(f"Failed to initialize service {sm.name}")
                        sm.stop()
                        self.managers.remove(sm)
                    elif (
                        sm.service_expected_state == ServiceState.RUNNING
                        and sm.service_prev_state == ServiceState.INITIALIZED
                    ):
                        self.logger.error(f"Failed to start service {sm.name}")
                    sm.service_state = ServiceState.FAILED

                if sm.service_state == ServiceState.RESET:
                    sm.service_init()
                    continue
                elif sm.service_state == ServiceState.INITIALIZED:
                    sm.service_start()
                    continue
                elif sm.service_state == ServiceState.RUNNING:
                    self.logger.debug(
                        f"service {sm.name} is in {sm.service_state} state"
                    )
                    pass  # good
                elif (
                    sm.service_state == ServiceState.STOPPED
                    or sm.service_state == ServiceState.FAILED
                    or sm.service_state == ServiceState.UNKNOWN
                    or sm.service_state == ServiceState.DEAD
                ):
                    self.logger.error(
                        f"service {sm.name} is in {sm.service_state} "
                        f"state, reason: {sm.service_reason}"
                    )
                    sm.restart()

                break

    def run(self) -> None:
        try:
            self.logger.info("Starting services")
            self._populate_services()

            for sm in self.managers:
                sm.start()

            systemd.daemon.notify("READY=1")
            self.logger.info("Uploaderd started")

            while self.managers:
                time_init = time.perf_counter()

                self._services_loop()

                # sleep if took less than BASE_TIMEOUT seconds
                time_left = self.timeout - (time.perf_counter() - time_init)
                if time_left > 0:
                    self.logger.debug(f"go to sleep for {time_left} seconds")
                    time.sleep(time_left)
        except Exception as error:
            self.logger.error(f"Exception occured while run uplodaerd: {error}")
            sys.exit(1)
        finally:
            for sm in self.managers:
                sm.stop()
