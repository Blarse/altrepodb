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
from datetime import datetime
from typing import Generator, Optional, Union, Any
from dataclasses import dataclass, field

from .logger import LoggerProtocol, _LoggerOptional, FakeLogger, ConsoleLogger
from .exceptions import RaisingThreadError

# Logger
# DEFAULT_LOGGER = FakeLogger
DEFAULT_LOGGER = ConsoleLogger  # FIXME: change it before release 

# Types
_StringOrPath = Union[str, Path]

#  Classes
class RaisingTread(threading.Thread):
    """Base threading class that raises exception stored in self.exc at join()"""

    def __init__(self, *args, **kwargs):
        self.exc: Optional[Exception] = None
        self.exc_message: str = ""
        self.exc_traceback: Any = None
        super().__init__(*args, **kwargs)

    def join(self):
        super().join()
        if self.exc:
            raise RaisingThreadError(
                message=self.exc_message, traceback=self.exc_traceback
            ) from self.exc


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


@dataclass
class PkgHash:
    sf: Optional[bytes] = None
    md5: Optional[bytes] = None
    sha1: Optional[bytes] = None
    sha256: Optional[bytes] = None
    blake2b: Optional[bytes] = None

@dataclass(frozen=True)
class PkgInfo:
    name: str
    evr: str
    file: str
    srpm: str
    arch: str

@dataclass
class TaskSubtask:
    task_id: int
    subtask_id: int
    task_repo: str = ""
    task_owner: str = ""
    task_changed: Optional[datetime] = None
    subtask_changed: Optional[datetime] = None
    userid: str = ""
    type: str = ""
    sid: str = ""
    dir: str = ""
    package: str = ""
    pkg_from: str = ""
    tag_author: str = ""
    tag_id: str = ""
    tag_name: str = ""
    srpm: str = ""
    srpm_name: str = ""
    srpm_evr: str = ""

@dataclass
class TaskState:
    task_id: int
    task_try: int
    task_iter: int
    state: str
    changed: Optional[datetime] = None
    runby: str = ""
    depends: list[int] = field(default_factory=list)
    prev: int = 0
    shared: int = 0
    testonly: int = 0
    failearly: int = 0
    message: str = ""
    version: str = ""

@dataclass
class TaskApprovals:
    task_id: int
    subtask_id: int
    type: str
    name: str = ""
    date: Optional[datetime] = None
    message: str = ""
    revoked: int = 0

@dataclass
class TaskIteration:
    task_id: int
    subtask_id: int
    subtask_arch: str
    task_changed: Optional[datetime] = None
    titer_ts: Optional[datetime] = None
    titer_status: str = ""
    task_try: int = 0
    task_iter: int = 0
    titer_srpm: str = ""
    titer_rpms: list[str] = field(default_factory=list)
    # FIXME: mmh(SHA1) should be replaced by something to work with snowflake_id's
    titer_chroot_base: list[int] = field(default_factory=list) 
    titer_chroot_br: list[int] = field(default_factory=list)

@dataclass
class TaskPlan:
    hashes: dict[str, int]
    pkg_add: dict[str, dict[str, PkgInfo]]
    pkg_del: dict[str, dict[str, PkgInfo]]
    hash_add: dict[str, dict[str, bytes]]
    hash_del: dict[str, dict[str, bytes]]

@dataclass
class TaskLog:
    type: str
    path: str
    hash: int
    hash_string: str

@dataclass
class Task:
    id: int
    subtasks: list[TaskSubtask]
    state: TaskState
    approvals: TaskApprovals
    iterations: list[TaskIteration]
    logs: list[TaskLog]
    arepo: list[str]
    plan: TaskPlan
    pkg_hashes: dict[str, PkgHash]
