# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021 BaseALT Ltd
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

from datetime import datetime
from typing import Optional, Protocol, Union


# Logger protocol and instances
class LoggerProtocol(Protocol):
    def debug(self, message: str, *args, **kwargs) -> None:
        raise NotImplementedError

    def info(self, message: str, *args, **kwargs) -> None:
        raise NotImplementedError

    def warning(self, message: str, *args, **kwargs) -> None:
        raise NotImplementedError

    def error(self, message: str, *args, **kwargs) -> None:
        raise NotImplementedError

    def critical(self, message: str, *args, **kwargs) -> None:
        raise NotImplementedError

    def setLevel(self, level: Union[int, str]) -> None:
        raise NotImplementedError


class FakeLogger(LoggerProtocol):
    """Fake logger class."""

    def debug(self, message: str, *args, **kwargs) -> None:
        pass

    def info(self, message: str, *args, **kwargs) -> None:
        pass

    def warning(self, message: str, *args, **kwargs) -> None:
        pass

    def error(self, message: str, *args, **kwargs) -> None:
        pass

    def critical(self, message: str, *args, **kwargs) -> None:
        pass

    def setLevel(self, level: Union[int, str]) -> None:
        pass


class ConsoleLogger(LoggerProtocol):
    """Simple console logger class. Mostly compatible with logging.Logger."""

    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0

    _levelToName = {
        CRITICAL: 'CRITICAL',
        ERROR: 'ERROR',
        WARNING: 'WARNING',
        INFO: 'INFO',
        DEBUG: 'DEBUG',
        NOTSET: 'NOTSET',
    }
    _nameToLevel = {
        'CRITICAL': CRITICAL,
        'ERROR': ERROR,
        'WARN': WARNING,
        'WARNING': WARNING,
        'INFO': INFO,
        'DEBUG': DEBUG,
        'NOTSET': NOTSET,
    }
    _level = NOTSET

    def _log(self, severity: int, message: str) -> None:
        if severity >= self._level:
            timestamp = datetime.now().isoformat(sep=" ", timespec="milliseconds")
            print(f"{timestamp} : {severity:8} : {message}")

    def debug(self, message: str, *args, **kwargs) -> None:
        self._log(self.DEBUG, message)

    def info(self, message: str, *args, **kwargs) -> None:
        self._log(self.INFO, message)

    def warning(self, message: str, *args, **kwargs) -> None:
        self._log(self.WARNING, message)

    def error(self, message: str, *args, **kwargs) -> None:
        self._log(self.ERROR, message)

    def critical(self, message: str, *args, **kwargs) -> None:
        self._log(self.CRITICAL, message)

    def setLevel(self, level: Union[int, str]) -> None:
        if isinstance(level, int):
            if level not in self._levelToName:
                raise ValueError(f"Incorrect logging level value: {level}")
            self._level = level
        if isinstance(level, str):
            if level not in self._nameToLevel:
                raise ValueError(f"Incorrect logging level value: {level}")
            self._level = self._nameToLevel.get(level, self.NOTSET)

# custom classes
_LoggerOptional = Optional[LoggerProtocol]
