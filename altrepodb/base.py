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

import threading
from pathlib import Path
from datetime import datetime
from typing import Iterator, Optional, Union, Any
from dataclasses import dataclass, field, asdict

from .logger import LoggerOptional
from .exceptions import RaisingThreadError


# Types
StringOrPath = Union[str, Path]


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

    def __init__(self, iter: Iterator):
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
    hash: int = 0
    name: str = ""
    arch: str = ""
    iname: Path = Path()
    epoch: int = 0
    version: str = ""
    release: str = ""
    disttag: str = ""
    is_srpm: bool = False
    buildtime: int = 0


@dataclass(frozen=True)
class File:
    md5: bytes = b""
    name: str = ""
    size: int = 0
    linkto: str = ""
    flag: int = 0
    lang: str = ""
    mode: int = 0
    rdev: int = 0
    mtime: int = 0
    class_: str = ""
    device: int = 0
    username: str = ""
    groupname: str = ""
    verifyflag: int = 0


@dataclass
class DatabaseConfig:
    host: str = "localhost"
    port: int = 9000
    name: str = "default"
    user: str = "default"
    password: str = ""


@dataclass
class PkgHash:
    sf: Optional[int] = None
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
    comp: str
    path: str
    subtask_id: int


@dataclass
class ImageProcessorConfig:
    path: StringOrPath
    logger: LoggerOptional
    dbconfig: DatabaseConfig
    debug: bool = False
    force: bool = False
    dryrun: bool = False


@dataclass
class PackageSet:
    name: str
    date: datetime
    uuid: str
    puuid: str
    ruuid: str
    depth: int
    complete: int
    tag: str = ""
    kw_args: dict[str, str] = field(default_factory=dict)
    package_hashes: list[int] = field(default_factory=list)


@dataclass
class ImageMeta:
    url: str
    arch: str
    date: datetime
    file: str
    branch: str
    flavor: str
    edition: str
    variant: str
    platform: str
    release: str
    version_major: int
    version_minor: int
    version_sub: int
    image_type: str


def stringify_image_meta(meta: ImageMeta) -> dict[str, str]:
    """Convert ImageMeta dataclass to dictionary of strings."""

    t = asdict(meta)
    for k, v in t.items():
        if isinstance(v, datetime):
            t[k] = v.isoformat()
        else:
            t[k] = str(v)

    return t
