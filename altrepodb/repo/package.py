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

import rpm
import time
import base64
import itertools
import multiprocessing as mp
from dataclasses import asdict
from typing import Any, Union

from altrpm import extractSpecFromRPM

from altrepodb.logger import LoggerProtocol
from altrepodb.database import DatabaseClient

from .base import PkgHash
from .mapper import (
    ChangelogRecord,
    get_package_map,
    get_file_map,
    get_provide_map,
    get_require_map,
    get_conflict_map,
    get_obsolete_map,
    unpack_map,
    rpm_header,
)


class PackageHandler:
    """Handle package header parsing and insertion to DB."""

    def __init__(self, conn: DatabaseClient, logger: LoggerProtocol):
        self.conn = conn
        self.logger = logger

    @staticmethod
    def get_header(rpmfile: str) -> rpm_header:
        # return readHeaderFromRPM(rpmfile)
        ts = rpm.TransactionSet()
        return ts.hdrFromFdno(rpmfile)

    def insert_package(self, hdr: rpm_header, pkg_file: str, **kwargs) -> None:
        """Insert information about package into database.

        Also:
        insert packager, files, requires, provides, confilcts, obsolets
        """
        map_package = get_package_map(hdr)
        map_package.update(**kwargs)
        # formatting changelog
        chlog: list[ChangelogRecord] = map_package["pkg_changelog"]
        del map_package["pkg_changelog"]
        map_package["pkg_changelog.date"] = []
        map_package["pkg_changelog.name"] = []
        map_package["pkg_changelog.evr"] = []
        map_package["pkg_changelog.hash"] = []

        for el in chlog:
            map_package["pkg_changelog.date"].append(el.date)
            map_package["pkg_changelog.name"].append(el.name)
            map_package["pkg_changelog.evr"].append(el.evr)
            map_package["pkg_changelog.hash"].append(el.hash)

        payload = [
            {"chlog_hash": r[0], "chlog_text": r[1]}
            for r in {(el.hash, el.text) for el in chlog}
        ]

        self.conn.execute("""INSERT INTO Changelog_buffer (*) VALUES""", payload)

        sql_insert = "INSERT INTO Packages_buffer ({0}) VALUES".format(
            ", ".join(map_package.keys())
        )

        pkghash = map_package["pkg_hash"]

        self.insert_file(pkghash, hdr)

        map_require = get_require_map(hdr)
        self.insert_list(map_require, pkghash, "require")

        map_conflict = get_conflict_map(hdr)
        self.insert_list(map_conflict, pkghash, "conflict")

        map_obsolete = get_obsolete_map(hdr)
        self.insert_list(map_obsolete, pkghash, "obsolete")

        map_provide = get_provide_map(hdr)
        self.insert_list(map_provide, pkghash, "provide")

        self.conn.execute(sql_insert, [map_package])

        if map_package["pkg_sourcepackage"] == 1:
            self.insert_specfile(pkg_file, map_package)

        return pkghash

    def _extract_spec_file(self, fname: str) -> tuple[Any, bytes]:
        """Extracts spec file from SRPM using subprocess to force memory release."""

        def _extract_spec_sp(fname: str, q: mp.Queue):
            q.put(extractSpecFromRPM(fname, raw=True))

        q = mp.Queue()
        p = mp.Process(target=_extract_spec_sp, args=(fname, q))
        p.start()
        spec_file, spec_contents = q.get()
        p.join

        return spec_file, spec_contents

    def insert_specfile(self, pkg_file: str, pkg_map: dict[str, Any]) -> None:
        self.logger.debug(f"extracting spec file form {pkg_map['pkg_filename']}")
        st = time.time()
        spec_file, spec_contents = self._extract_spec_file(pkg_file)
        self.logger.debug(
            f"headers and spec file extracted in {(time.time() - st):.3f} seconds"
        )
        self.logger.debug(f"Got {spec_file.name} spec file {spec_file.size} bytes long")
        st = time.time()
        self.conn.execute(
            "INSERT INTO Specfiles_insert (*) VALUES",
            [
                {
                    "pkg_hash": pkg_map["pkg_hash"],
                    "pkg_name": pkg_map["pkg_name"],
                    "pkg_epoch": pkg_map["pkg_epoch"],
                    "pkg_version": pkg_map["pkg_version"],
                    "pkg_release": pkg_map["pkg_release"],
                    "specfile_name": spec_file.name,
                    "specfile_date": spec_file.mtime,
                    "specfile_content_base64": base64.b64encode(spec_contents),
                },
            ],
        )
        self.logger.debug(f"spec file loaded to DB in {(time.time() - st):.3f} seconds")

    def insert_file(self, pkghash: int, hdr: rpm_header) -> None:
        map_file = get_file_map(hdr)
        map_file["pkg_hash"] = itertools.cycle([pkghash])
        data = unpack_map(map_file)
        self.conn.execute(
            "INSERT INTO Files_insert ({0}) VALUES".format(", ".join(map_file.keys())),
            data,
        )
        self.logger.debug("insert file for pkghash: {0}".format(pkghash))

    def insert_list(self, tagmap: dict[str, Any], pkghash: int, dptype: str) -> None:
        """Insert list as batch."""
        tagmap["pkg_hash"] = itertools.cycle([pkghash])
        tagmap["dp_type"] = itertools.cycle([dptype])
        data = unpack_map(tagmap)
        self.conn.execute(
            "INSERT INTO Depends_buffer ({0}) VALUES".format(", ".join(tagmap.keys())),
            data,
        )
        self.logger.debug(
            "insert list into: {0} for pkghash: {1}".format(dptype, pkghash)
        )

    @staticmethod
    def convert_hashes(pkghash: PkgHash) -> dict[str, Union[int, bytes]]:
        """Convert PkgHash instance to dictionary for compatibility."""

        hashes = asdict(pkghash)
        hashes["mmh"] = hashes["sf"]
        del hashes["sf"]
        return hashes

    def insert_pkg_hashes(self, pkg_hashes: dict[Any, dict[str, Union[int, bytes]]]) -> None:
        """Inserts multiple packages hashes to DB

        Args:
            conn (connection): ClickHouse driver connection object
            pkg_hashes (dict[dict]): dictionary of packages hashes
        """
        payload = []
        for v in pkg_hashes.values():
            payload.append(
                {
                    "pkgh_mmh": v["mmh"],
                    "pkgh_md5": v["md5"],
                    "pkgh_sha1": v["sha1"],
                    "pkgh_sha256": v["sha256"],
                    "pkgh_blake2b": v["blake2b"],
                }
            )
        settings = {"strings_as_bytes": True}
        self.conn.execute(
            "INSERT INTO PackageHash_buffer (*) VALUES", payload, settings=settings
        )

    def insert_pkg_hash_single(self, pkg_hash: dict[str, Union[int, bytes]]) -> None:
        """Insert single package hashes to DB

        Args:
            conn (connection): ClickHouse driver connection object
            pkg_hash (dict): dictionary of single package hashes
        """
        settings = {"strings_as_bytes": True}
        self.conn.execute(
            "INSERT INTO PackageHash_buffer (*) VALUES",
            [
                {
                    "pkgh_mmh": pkg_hash["mmh"],
                    "pkgh_md5": pkg_hash["md5"],
                    "pkgh_sha1": pkg_hash["sha1"],
                    "pkgh_sha256": pkg_hash["sha256"],
                    "pkgh_blake2b": pkg_hash["blake2b"],
                }
            ],
            settings=settings,
        )
