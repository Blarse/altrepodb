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

from altrepodb.database import DatabaseClient

from .base import PkgHash


class RepoLoadHelper:
    """Helper for repository structure processing and loading to DB."""

    def __init__(self, conn: DatabaseClient):
        self.conn = conn
        self.logger = logging.getLogger(__name__ + "." + self.__class__.__name__)

    @staticmethod
    def init_cache(
        src_hashes: dict[str, PkgHash], bin_hashes: dict[str, PkgHash]
    ) -> set[int]:
        cache = set()
        for v in src_hashes.values():
            if v.sf not in (0, None):
                cache.add(v.sf)
        for v in bin_hashes.values():
            if v.sf not in (0, None):
                cache.add(v.sf)

        return cache

    def init_hash_temp_table(self, hashes: dict[str, PkgHash]) -> None:
        payload = []
        self.conn.execute(
            """
CREATE TEMPORARY TABLE IF NOT EXISTS _tmpPkgHash
(
    name    String,
    md5     FixedString(16),
    sha256  FixedString(32)
)"""  # noqa: E122
        )
        for k in hashes:
            # workaround to a possible bug in the repository structure
            # if files/list/*.hash.* files contain missing packages
            if hashes[k].md5 is None:
                continue
            payload.append(
                {"name": k, "md5": hashes[k].md5, "sha256": hashes[k].sha256}
            )
        self.conn.execute("INSERT INTO _tmpPkgHash (*) VALUES", payload)
        self.logger.debug(f"Inserted {len(payload)} hashes into _tmpPkgHash")
        # Free memory immediatelly
        del payload

    def update_hases_from_db(self, repo_cache: dict[str, PkgHash]) -> None:
        result = self.conn.execute(
            """
SELECT t1.name, t1.md5, t2.mmh, t2.sha1
FROM _tmpPkgHash AS t1
LEFT JOIN
(
    SELECT pkgh_md5 AS md5, pkgh_mmh AS mmh, pkgh_sha1 AS sha1
    FROM PackageHash_buffer
) AS t2
ON t1.md5 = t2.md5""",  # noqa: E122
            settings={"strings_as_bytes": True},
        )
        cnt1 = cnt2 = 0
        if len(result):  # type: ignore
            for (k, *v) in result:  # type: ignore
                if len(v) == 3:
                    kk = k.decode("utf-8")
                    if kk in repo_cache.keys():
                        if v[1] != 0:
                            repo_cache[kk].sf = v[1]
                            repo_cache[kk].sha1 = v[2]
                            cnt1 += 1
                        else:
                            repo_cache[kk].sf = 0
                            repo_cache[kk].sha1 = None
                            cnt2 += 1
        self.logger.debug(
            f"Requested {len(result)} package hashes from database. "  # type: ignore
            f"For {len(repo_cache)} packages {cnt1} hashes found in "
            f"'PackagaeHash_buffer' table, {cnt2} packages not loaded yet."
        )

    def check_repo_date_name_in_db(
        self, pkgset_name: str, pkgset_date: datetime.date
    ) -> bool:
        result = self.conn.execute(
            f"SELECT COUNT(*) FROM PackageSetName WHERE "
            f"pkgset_nodename='{pkgset_name}' AND pkgset_date='{pkgset_date}'"
        )
        return result[0][0] != 0  # type: ignore
