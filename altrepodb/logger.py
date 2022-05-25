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

import logging
import datetime
import configparser
from logging import handlers
from dataclasses import dataclass
from typing import Optional, Any


# constants
PROJECT_NAME = "altrepodb"
DEFAULT_LOG_LEVEL = logging.INFO
LOGGER_CONFIG_OPTIONS = [
    ("log_to_file", bool),
    ("log_to_syslog", bool),
    ("log_to_console", bool),
    ("syslog_ident", str),
]


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


# custom classes
LoggerOptional = Optional[logging.Logger]


def get_logger(
    name: str,
    tag: Optional[str] = None,
    date: Optional[datetime.date] = None,
    log_to_file: bool = False,
    log_to_stderr: bool = True,
    log_to_syslog: bool = False,
    logging_level: int = DEFAULT_LOG_LEVEL,
    syslog_ident: str = PROJECT_NAME
) -> logging.Logger:
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
            syslog_handler.ident = syslog_ident
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


def parse_logger_config(fname: str, options: list[tuple[str, type]]) -> dict[str, Any]:
    """Parses logging options from configuration file. Options are
    searched in 'LOGGING' section, but could be found in 'DEFAULT' section as well.
    Options passed with 'bool' type are gathered with configparser.getboolean() function.

    Args:
        fname (str): config file name
        options (list[tuple[str, type]]): list of tuples of `option_name` and `option_type`.

    Returns:
        dict[str, Any]: result dictionary as `option_name`:`option_value`
    """
    res = {}
    cfg = configparser.ConfigParser()
    try:
        with open(fname) as f:
            cfg.read_file(f)
    except Exception:
        return res

    if cfg.has_section("LOGGING"):
        section = cfg["LOGGING"]
    else:
        section = cfg["DEFAULT"]

    for opt in options:
        if opt[1] == bool:
            try:
                # values evaluated as True : '1', 'true', 'yes', 'on'
                # values evaluated as False : '0', 'no', 'false', 'off'
                v = section.getboolean(opt[0])
            except ValueError:
                v = None
        else:
            v = section.get(opt[0])
        if v is not None:
            res[opt[0]] = v

    return res


def get_config_logger(
    name: str,
    tag: Optional[str] = None,
    date: Optional[datetime.date] = None,
    config: Optional[str] = None
) -> logging.Logger:
    """Get logger instance with options parsed from configuration file.
    If `config` is None the default values are used.

    Args:
        name (str): module name (also used as part of log file name)
        tag (Optional[str], optional): tag (used as part of log file name). Defaults to None.
        date (Optional[datetime.date], optional): date (used as part of log file name). Defaults to None.
        config (Optional[str], optional): path to configuration file. Defaults to None.

    Returns:
        logging.Logger instance
    """

    opts = {}
    if config is not None:
        opts = parse_logger_config(config, LOGGER_CONFIG_OPTIONS)
    return get_logger(
        name=name,
        tag=tag,
        date=date,
        log_to_file=opts.get("log_to_file", False),
        log_to_stderr=opts.get("log_to_console", True),
        log_to_syslog=opts.get("log_to_syslog", False),
        syslog_ident=opts.get("syslog_ident", PROJECT_NAME),
    )
