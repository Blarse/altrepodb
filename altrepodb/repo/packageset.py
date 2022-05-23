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

import datetime
from typing import Optional, Union

from altrepodb.logger import LoggerProtocol
from altrepodb.database import DatabaseClient


class PackageSetHandler:
    """Handle package set records insertion to DB."""

    def __init__(self, conn: DatabaseClient, logger: LoggerProtocol):
        self.conn = conn
        self.logger = logger

    def insert_pkgset_name(
        self,
        name: str,
        uuid: str,
        puuid: str,
        ruuid: str,
        depth: int,
        tag: str,
        date: Optional[datetime.datetime],
        complete: int,
        kw_args: dict[str, str],
    ):
        if date is None:
            date = datetime.datetime.now().replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        self.conn.execute(
            "INSERT INTO PackageSetName (*) VALUES",
            [
                {
                    "pkgset_uuid": uuid,
                    "pkgset_puuid": puuid,
                    "pkgset_ruuid": ruuid,
                    "pkgset_depth": depth,
                    "pkgset_nodename": name,
                    "pkgset_date": date,
                    "pkgset_tag": tag,
                    "pkgset_complete": complete,
                    "pkgset_kv.k": [k for k, v in kw_args.items() if v is not None],
                    "pkgset_kv.v": [v for k, v in kw_args.items() if v is not None],
                },
            ],
        )
        self.logger.debug("insert package set name uuid: {0}".format(uuid))

    def insert_pkgset(self, uuid: str, pkghash: Union[list[int], set[int]]) -> None:
        self.conn.execute(
            "INSERT INTO PackageSet_buffer (pkgset_uuid, pkg_hash) VALUES",
            [dict(pkgset_uuid=uuid, pkg_hash=p) for p in pkghash],
        )
        self.logger.debug(
            "insert package set uuid: {0}, pkg_hash: {1}".format(uuid, len(pkghash))
        )
