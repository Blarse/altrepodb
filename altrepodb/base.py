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

import threading
from pathlib import Path
from typing import Generator, Protocol, Union, Any
from dataclasses import dataclass

from .logger import _LoggerOptional, FakeLogger, ConsoleLogger
from .exceptions import RaisingThreadError

# Logger
# DEFAULT_LOGGER = FakeLogger
DEFAULT_LOGGER = ConsoleLogger

# Types
_StringOrPath = Union[str, Path]

#  Classes
class RaisingTread(threading.Thread):
    """Base threading class that raises exception stored in self.exc at join()"""

    def __init__(self, *args, **kwargs):
        self.exc = None
        self.exc_message = None
        self.exc_traceback = None
        super().__init__(*args, **kwargs)

    def join(self):
        super().join()
        if self.exc:
            raise RaisingThreadError(
                message=self.exc_message, traceback=self.exc_traceback
            ) from self.exc  # type: ignore


class LockedIterator:
    """Thread safe iterator wraper."""

    def __init__(self, it):
        self.it = it
        self.lock = threading.Lock()

    def __iter__(self):
        return self

    def __next__(self):
        with self.lock:
            return next(self.it)


class GeneratorWrapper:
    """Wraps generator function and allow to test it's emptyness at any time."""

    def __init__(self, iter: Generator):
        self.source = iter
        self.stored = False

    def __iter__(self):
        return self

    def __bool__(self):
        if self.stored:
            return True
        try:
            self.value = next(self.source)
            self.stored = True
        except StopIteration:
            return False
        return True

    def __next__(self):
        if self.stored:
            self.stored = False
            return self.value
        return next(self.source)

# Dataclasses
@dataclass(frozen=True)
class Package:
    hash: int
    name: str
    arch: str
    iname: Path
    epoch: int
    version: str
    release: str
    disttag: str
    is_srpm: bool
    buildtime: int


@dataclass(frozen=True)
class File:
    md5: bytes
    name: str
    size: int
    linkto: str
    flag: int
    lang: str
    mode: int
    rdev: int
    mtime: int
    class_: str
    device: int
    username: str
    groupname: str
    verifyflag: int


@dataclass
class DatabaseConfig:
    host: str = "localhost"
    port: int = 9000
    name: str = "default"
    user: str = "default"
    password: str = ""


@dataclass
class TaskProcessorConfig:
    id: int
    path: _StringOrPath
    dbconfig: DatabaseConfig
    logger: _LoggerOptional
    debug: bool = False
    flush: bool = True
    force: bool = False
    workers: int = 4
    dumpjson: bool = False


@dataclass
class RepoProcessorConfig:
    name: str
    path: _StringOrPath
    date: str
    dbconfig: DatabaseConfig
    logger: _LoggerOptional
    tag: str = ""
    debug: bool = False
    force: bool = False
    verbose: bool = False
    workers: int = 8


@dataclass
class ISOProcessorConfig:
    name: str
    path: _StringOrPath
    logger: _LoggerOptional
    debug: bool = False
    force: bool = False
