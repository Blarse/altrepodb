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

from enum import Enum, IntEnum, auto
from dataclasses import dataclass
from typing import Any


class ServiceAction(IntEnum):
    UNKNOWN = 0
    INIT = auto()
    START = auto()
    STOP = auto()
    GET_STATE = auto()
    KILL = auto()
    REPORT = auto()


class ServiceState(IntEnum):
    UNKNOWN = 0
    RESET = auto()
    INITIALIZED = auto()
    RUNNING = auto()
    FAILED = auto()
    STOPPED = auto()
    STOPPING = auto()
    DEAD = auto()


@dataclass
class Message:
    msg: int = 0
    reason: str = ""
    payload: Any = None


class NotifierMessageSeverity(Enum):
    INFO = auto()
    WARNING = auto()
    CRITICAL = auto()


class NotifierMessageType(Enum):
    MESSAGE = auto()
    SERVICE_ERROR = auto()
    SERVICE_WORKER_ERROR = auto()


@dataclass(frozen=True)
class NotifierMessageReason:
    ERROR = "error"
    NOTIFY = "notify"


@dataclass(frozen=True)
class WorkStatus:
    NEW = "new"
    DONE = "done"
    FAILED = "failed"


@dataclass
class NotifierMessage:
    subject: str
    severity: NotifierMessageSeverity
    type: NotifierMessageType
    message: str
    timestamp: float
    payload: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "severity": self.severity.name,
            "type": self.type.name,
            "message": self.message,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }


@dataclass
class ServiceConfig:
    name: str
    config_path: str
    debug: bool = False
