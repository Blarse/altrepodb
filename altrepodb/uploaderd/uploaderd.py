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
import logging
import systemd.daemon
from typing import Optional
from pathlib import Path
from dataclasses import dataclass

from .base import ServiceState
from .manager import ServiceManager

NAME = "altrepodb.uploaderd"
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
        self._check_config()

    def _check_config(self):
        if not Path(self.config_file).is_file():
            self.logger.critical(f"'{self.config_file}' not found")
            raise UploaderDaemonError

        if not Path(self.services_config_dir).is_dir():
            self.logger.critical(f"'{self.services_config_dir}' is not a valid directory")
            raise UploaderDaemonError

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

        if "services" not in config:
            self.logger.error("No services configuration found")
            raise UploaderDaemonError

        for service_entry in config["services"]:
            service_config_file = Path(self.services_config_dir).joinpath(
                service_entry["config"]
            )

            if not service_config_file.is_file():
                self.logger.error(f"'{service_config_file.name}' not found")
                raise UploaderDaemonError

            self.logger.debug(f"Preparing {service_entry['name']} service")
            self.managers.append(
                ServiceManager(
                    service_entry["name"],
                    str(service_config_file),
                )
            )

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

    def shutdown(self, signum, frame):
        self.logger.info("Received SIGTERM signal")
        systemd.daemon.notify("STOPPING=1")
        for sm in self.managers:
            self.logger.info(f"Stopping service {sm.name}")
            sm.stop()
            self.logger.info(f"Service {sm.name} stopped")
        systemd.daemon.notify("STATUS=All services stopped")
        raise SystemExit(0)

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
            self.logger.critical(f"Exception occured while run uplodaerd: {error}")
            raise UploaderDaemonError from error
        finally:
            for sm in self.managers:
                sm.stop()