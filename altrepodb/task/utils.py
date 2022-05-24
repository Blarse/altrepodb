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
from typing import Iterable

from altrepodb.database import DatabaseClient

logger = logging.getLogger(__name__)


def init_cache(conn: DatabaseClient, packages: Iterable[str]):
    result = conn.execute(
        """CREATE TEMPORARY TABLE IF NOT EXISTS PkgFNameTmp (pkg_filename String)"""
    )
    payload = []
    for pkg_name in [x.split("/")[-1] for x in packages]:
        payload.append({"pkg_filename": pkg_name})

    result = conn.execute("INSERT INTO PkgFNameTmp (*) VALUES", payload)

    logger.debug(f"Inserted {len(payload)} 'pkg_filename's into PkgFNameTmp")

    result = conn.execute(
        """SELECT pkg_hash
           FROM Packages_buffer
           WHERE pkg_filename IN
             (SELECT * FROM PkgFNameTmp)"""
    )

    return {i[0] for i in result}
