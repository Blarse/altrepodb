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
from .manager import ServiceManager, ServiceManagerError
from .notifier import NotifierManager

from altrepodb.settings import (
    DEFAULT_UPLOADERD_CONFIG_FILE,
    DEFAULT_SERVICE_CONF_DIR,
    DEFAULT_BASE_TIMEOUT,
)

NAME = "altrepodb.uploaderd"


class UploaderDaemonError(Exception):
    pass


@dataclass
class UploaderDaemonConfig:
    config_file: str = DEFAULT_UPLOADERD_CONFIG_FILE
    services_config_dir: str = DEFAULT_SERVICE_CONF_DIR
    service_timeout: int = DEFAULT_BASE_TIMEOUT
    logger: Optional[logging.Logger] = None


class UploaderDaemon:
    def __init__(self, config: UploaderDaemonConfig) -> None:
        self.config_file = config.config_file
        self.services_config_dir = config.services_config_dir
        self.timeout = config.service_timeout

        if config.logger:
            self.logger = config.logger
        else:
            self.logger = logging.getLogger(NAME)

        self.managers: list[ServiceManager] = []
        self._check_config()

        self.notifier: NotifierManager

    def _check_config(self):
        if not Path(self.config_file).is_file():
            self.logger.critical(f"'{self.config_file}' not found")
            raise UploaderDaemonError

        if not Path(self.services_config_dir).is_dir():
            self.logger.critical(
                f"'{self.services_config_dir}' is not a valid directory"
            )
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

        if "notifier" not in config:
            self.logger.error("Notifier service configuration not found")
            raise UploaderDaemonError

        self.notifier = NotifierManager(config["notifier"])

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
                    service_entry["name"], str(service_config_file), self.notifier
                )
            )

    def _initialize_services(self):
        for sm in self.managers:
            try:
                sm.initialize()
            except ServiceManagerError as e:
                self.logger.error(f"Failed to initialize service '{sm.name}' with {e}")
                raise UploaderDaemonError from e

    def _services_loop(self) -> None:
        for sm in self.managers:
            sm.get_service_state()
            self.logger.debug(f"service {sm.name} state: {sm.service_state.name}")

            if sm.service_state != ServiceState.RUNNING:
                self.logger.error(
                    f"service {sm.name} is in {sm.service_state.name} "
                    f"state, reason: {sm.service_reason}"
                )
                sm.restart()

    def shutdown(self, signum, frame):
        # FIXME: SIGTERM now handled through service's process handler
        self.logger.info("Shutting down uploaderd service...")
        systemd.daemon.notify("STOPPING=1")
        for sm in self.managers[:]:
            self.logger.info(f"Stopping service {sm.name}")
            sm.stop()
            self.logger.info(f"Service {sm.name} stopped")
            self.managers.remove(sm)
        systemd.daemon.notify("STATUS=All services stopped")
        raise SystemExit(0)

    def run(self) -> None:
        try:
            self.logger.info("Starting services")
            self._populate_services()
            self._initialize_services()

            self.notifier.start()

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
                    self.logger.debug(f"go to sleep for {time_left:.3f} seconds")
                    time.sleep(time_left)
        except (ServiceManagerError, Exception) as error:
            self.logger.critical(f"Exception occured while run uplodaerd: {error}")
            raise UploaderDaemonError(f"Error: {error}")
        finally:
            systemd.daemon.notify("STOPPING=1")
            self.notifier.stop()
            for sm in self.managers[:]:
                self.logger.info(f"Stopping service {sm.name}")
                sm.stop()
                self.logger.info(f"Service {sm.name} stopped")
                self.managers.remove(sm)
            systemd.daemon.notify("STATUS=All services stopped")
