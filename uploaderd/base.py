from enum import IntEnum, auto
from dataclasses import dataclass
from typing import Any


class ServiceAction(IntEnum):
    UNKNOWN = 0
    INIT = auto()
    START = auto()
    STOP = auto()
    GET_STATE = auto()
    KILL = auto()


class ServiceState(IntEnum):
    UNKNOWN = 0
    RESET = auto()
    INITIALIZED = auto()
    RUNNING = auto()
    FAILED = auto()
    STOPPED = auto()
    DEAD = auto()


@dataclass
class Message:
    msg: int = 0
    reason: str = ""
    payload: Any = None


@dataclass
class ServiceConfig:
    name: str
    config_path: str
    debug: bool = False
