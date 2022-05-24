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

from pathlib import Path
from datetime import datetime
from typing import Optional, Union, DefaultDict
from dataclasses import dataclass, field

from altrepodb.base import PkgHash, PkgInfo
from altrepodb.database import DatabaseConfig

StringOrPath = Union[str, Path]


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
    deleted: int = 0


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
class TaskApproval:
    task_id: int
    subtask_id: int
    type: str
    date: Optional[datetime] = None
    name: str = ""
    message: str = ""
    revoked: Optional[int] = None


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
    approvals: list[TaskApproval]
    iterations: list[TaskIteration]
    logs: list[TaskLog]
    arepo: list[str]
    plan: TaskPlan
    pkg_hashes: DefaultDict[str, PkgHash]


@dataclass
class TaskProcessorConfig:
    id: int
    path: StringOrPath
    dbconfig: DatabaseConfig
    logger: Optional[logging.Logger]
    debug: bool = False
    flush: bool = True
    force: bool = False
    workers: int = 4
    dumpjson: bool = False
