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
from pathlib import Path
from typing import Any, Union

from altrepodb.utils import cvt_ts_to_datetime
from altrepodb.repo.utils import convert
from altrepodb.repo.package import PackageHandler
from .base import StringOrPath


class TaskFromFileSystem:
    """Provides functions to read task's elements from filesystem."""

    def __init__(self, path: StringOrPath, logger: logging.Logger):
        self.logger = logger
        self.path = Path(path)

    def _get_content(self, path: StringOrPath, status: bool = False) -> Any:
        r = None
        if status:
            if Path(path).exists():
                return True
            else:
                return False
        try:
            r = Path(path).read_bytes()
        except IsADirectoryError:
            # return directory listing
            return [x for x in Path(path).iterdir()]
        except FileNotFoundError as e:
            self.logger.debug(str(e))
            return None
        except Exception as e:
            self.logger.error(f"{e} - {path}")
            return None
        return r

    def get(self, path: StringOrPath) -> Any:
        p = Path.joinpath(self.path, path)
        r = self._get_content(p, status=False)
        return convert(r)

    def get_text(self, path: StringOrPath, default: str = "") -> str:
        t = self.get(path)
        return t.strip() if t else default

    def get_int(self, path: StringOrPath, default: int = 0) -> int:
        t = self.get(path)
        return int(t) if t else default

    def check(self) -> bool:
        return self._get_content(self.path, status=True)

    def check_file(self, path: StringOrPath) -> bool:
        p = Path.joinpath(self.path, path)
        return self._get_content(p, status=True)

    def get_bytes(self, path: StringOrPath) -> bytes:
        p = Path.joinpath(self.path, path)
        r = self._get_content(p, status=False)
        return r

    def get_file_mtime(self, path: StringOrPath) -> Union[None, datetime.datetime]:
        p = Path.joinpath(self.path, path)
        try:
            mtime = p.stat().st_mtime
        except FileNotFoundError:
            return None
        return cvt_ts_to_datetime(mtime, use_local_tz=False)

    def get_file_size(self, path: StringOrPath) -> int:
        p = Path.joinpath(self.path, path)
        try:
            file_size = p.stat().st_size
        except FileNotFoundError:
            return 0
        return file_size

    def get_header(self, path: StringOrPath) -> dict:
        return PackageHandler.get_header(str(Path.joinpath(self.path, path)))

    def get_file_path(self, path: StringOrPath) -> Path:
        return Path.joinpath(self.path, path)

    def file_exists_and_not_empty(self, path: StringOrPath) -> bool:
        p = Path.joinpath(self.path, path)
        if p.is_file() and p.stat().st_size > 0:
            return True
        else:
            return False

    def get_symlink_target(
        self, path: StringOrPath, name_only: bool = False
    ) -> Union[None, str]:
        symlink = Path.joinpath(self.path, path)
        if symlink.is_symlink():
            if name_only:
                return str(symlink.resolve().name)
            else:
                return str(symlink.resolve())
        else:
            return None
