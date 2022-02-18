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

import sys
import logging
import datetime
from logging import handlers
from dataclasses import dataclass
from typing import Optional, Protocol, Union, Any


# constants
PROJECT_NAME = "altrepodb"
DEFAULT_LOG_LEVEL = logging.INFO


@dataclass(frozen=True)
class LoggerLevel:
    """Simple logging level enum-like object compatible with logging module."""

    NOTSET = logging.NOTSET
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARN = logging.WARNING
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


# Logger protocol and instances
class LoggerProtocol(Protocol):
    def __init__(self, name: str, level: Any) -> None:
        raise NotImplementedError

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError

    def setLevel(self, level: Union[int, str]) -> None:
        raise NotImplementedError


class FakeLogger(LoggerProtocol):
    """Fake logger class."""

    def __init__(self, name: str, level: Any = None) -> None:
        pass

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        pass

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        pass

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        pass

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        pass

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        pass

    def setLevel(self, level: Union[int, str]) -> None:
        pass


class ConsoleLogger(LoggerProtocol):
    """Simple console logger class. Mostly compatible with logging.Logger."""

    _ll = LoggerLevel()
    _level = _ll.WARNING
    _handler = sys.stdout
    _levelToName = {
        _ll.CRITICAL: "CRITICAL",
        _ll.ERROR: "ERROR",
        _ll.WARNING: "WARNING",
        _ll.INFO: "INFO",
        _ll.DEBUG: "DEBUG",
        _ll.NOTSET: "NOTSET",
    }
    _nameToLevel = {
        "CRITICAL": _ll.CRITICAL,
        "ERROR": _ll.ERROR,
        "WARN": _ll.WARNING,
        "WARNING": _ll.WARNING,
        "INFO": _ll.INFO,
        "DEBUG": _ll.DEBUG,
        "NOTSET": _ll.NOTSET,
    }

    def __init__(self, name: str, level: Union[int, str] = "DEBUG") -> None:
        self.name = name
        self.setLevel(level)

    def _log(self, severity: int, message: str) -> None:
        if severity >= self._level:
            timestamp = datetime.datetime.now().isoformat(
                sep=" ", timespec="milliseconds"
            )
            print(
                f"{timestamp} : {self._levelToName[severity]:8} : {message}",
                file=self._handler,
            )

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(self._ll.DEBUG, msg)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(self._ll.INFO, msg)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(self._ll.WARNING, msg)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(self._ll.ERROR, msg)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._log(self._ll.CRITICAL, msg)

    def setLevel(self, level: Union[int, str]) -> None:
        if isinstance(level, int):
            if level not in self._levelToName:
                raise ValueError(f"Incorrect logging level value: {level}")
            self._level = level
        if isinstance(level, str):
            if level not in self._nameToLevel:
                raise ValueError(f"Incorrect logging level value: {level}")
            self._level = self._nameToLevel.get(level, self._ll.NOTSET)


# custom classes
_LoggerOptional = Optional[LoggerProtocol]


def get_logger(
    name: str,
    tag: Optional[str] = None,
    date: Optional[datetime.date] = None,
    log_to_file: bool = True,
    log_to_stderr: bool = True,
    log_to_syslog: bool = False,
    logging_level: int = DEFAULT_LOG_LEVEL
) -> LoggerProtocol:
    """Get logger instance with specific name as child of root logger.
    Creates root logger if it doesn't exists."""

    root_logger = logging.getLogger(PROJECT_NAME)
    root_logger.setLevel(logging_level)

    if date is None:
        date = datetime.date.today()
    if tag is not None:
        LOG_FILE = "{0}-{1}-{2}.log".format(name, tag, date.strftime("%Y-%m-%d"))
    else:
        LOG_FILE = "{0}-{1}.log".format(name, date.strftime("%Y-%m-%d"))

    if not len(root_logger.handlers):
        if log_to_stderr:
            # stream handler config
            fmt = logging.Formatter("%(asctime)s: %(message)s")
            stderr_handler = logging.StreamHandler()
            stderr_handler.setFormatter(fmt)
            root_logger.addHandler(stderr_handler)

        if log_to_syslog:
            # syslog handler config
            fmt = logging.Formatter(": %(levelname)-9s%(name)s: %(message)s")

            syslog_handler = handlers.SysLogHandler(
                address="/dev/log", facility=handlers.SysLogHandler.LOG_DAEMON
            )
            syslog_handler.ident = PROJECT_NAME
            syslog_handler.setFormatter(fmt)
            root_logger.addHandler(syslog_handler)

        if log_to_file:
            # file handler config
            fmt = logging.Formatter(
                "%(asctime)s %(levelname)-9s[%(threadName)s][%(module)s.%(funcName)s:%(lineno)d]: %(message)s"
            )

            file_handler = handlers.RotatingFileHandler(
                filename=LOG_FILE, maxBytes=2 ** 24, backupCount=10
            )
            file_handler.setFormatter(fmt)
            root_logger.addHandler(file_handler)
        # pass if no logging handlers enabled
        pass

    logger_name = ".".join((PROJECT_NAME, name))
    logger = logging.getLogger(logger_name)

    return logger  # type: ignore
