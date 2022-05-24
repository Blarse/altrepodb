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
from dataclasses import dataclass
from typing import Optional, Union
from pathlib import Path

from altrepodb.database import DatabaseConfig

# Types
StringOrPath = Union[str, Path]


@dataclass
class PkgHash:
    sf: Optional[int] = None
    md5: Optional[bytes] = None
    sha1: Optional[bytes] = None
    sha256: Optional[bytes] = None
    blake2b: Optional[bytes] = None


@dataclass
class RepoLeaf:
    name: str
    path: str
    uuid: str
    puuid: str


@dataclass
class RootRepoLeaf(RepoLeaf):
    kwargs: dict[str, str]


@dataclass
class SrcRepoLeaf(RepoLeaf):
    path: list[str]


@dataclass
class Repository:
    root: RootRepoLeaf
    src: SrcRepoLeaf
    archs: list[RepoLeaf]
    comps: list[RepoLeaf]
    src_hashes: dict[str, PkgHash]
    bin_hashes: dict[str, PkgHash]
    bin_pkgs: dict[tuple[str, str], tuple[str, ...]]
    use_blake2b: bool

    @property
    def all_archs(self):
        return {arch.name for arch in self.archs}

    @property
    def all_comps(self):
        return {comp.name for comp in self.comps}


@dataclass
class RepoProcessorConfig:
    name: str
    path: StringOrPath
    date: datetime.datetime
    dbconfig: DatabaseConfig
    logger: Optional[logging.Logger]
    tag: str = ""
    debug: bool = False
    force: bool = False
    verbose: bool = False
    workers: int = 8
