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
from pathlib import Path

from .altrpm import rpm as rpmt
from .base import Package, StringOrPath
from .utils import SupressStdoutStderr
from .repo.utils import convert
from .repo.mapper import detect_arch, snowflake_id_pkg


class RPMDBOpenError(Exception):
    """Rises when failed to open RPMDB from SquashFS image at ISO."""

    def __init__(self, path: StringOrPath = ""):
        self.path = str(path)
        super().__init__(f"Failed to open RPM DB in {self.path}")


class RPMDBPackages:
    """Reads RPM database and retrieves packages info."""

    def __init__(self, dbpath: StringOrPath):
        self.dbpath = str(dbpath)
        self.packages_list: list[Package] = []
        self.packages_count: int = 0
        self._read_rpm_db()

    def _read_rpm_db(self) -> None:
        # add macro to be used by RPM
        rpm.addMacro("_dbpath", self.dbpath)  # type: ignore
        # open RPM DB
        ts = rpm.TransactionSet()
        with SupressStdoutStderr():
            r = ts.openDB()
        if r != 0:
            raise RPMDBOpenError(self.dbpath)
        # remove macro for future cases
        rpm.delMacro("_dbpath")  # type: ignore
        # retrieve all packages from BDB
        hdrs = ts.dbMatch()
        for hdr in hdrs:
            self.packages_count += 1
            self.packages_list.append(
                Package(
                    iname=Path(),
                    hash=snowflake_id_pkg(hdr),
                    name=convert(hdr[rpmt.RPMTAG_NAME]),
                    epoch=convert(hdr[rpmt.RPMTAG_EPOCH], int),
                    version=convert(hdr[rpmt.RPMTAG_VERSION]),
                    release=convert(hdr[rpmt.RPMTAG_RELEASE]),
                    arch=detect_arch(hdr),
                    disttag=convert(hdr[rpmt.RPMTAG_DISTTAG]),
                    is_srpm=bool(hdr[rpmt.RPMTAG_SOURCEPACKAGE]),
                    buildtime=convert(hdr[rpmt.RPMTAG_BUILDTIME]),
                )
            )

    @property
    def packages(self):
        return self.packages_list

    @property
    def count(self):
        return self.packages_count

    @staticmethod
    def get_package_info(package: StringOrPath) -> Package:
        package_iname = Path(package)
        ts = rpm.TransactionSet()
        hdr = ts.hdrFromFdno(str(package_iname))
        pkg = Package(
            iname=package_iname,
            hash=snowflake_id_pkg(hdr),
            name=convert(hdr[rpmt.RPMTAG_NAME]),
            epoch=convert(hdr[rpmt.RPMTAG_EPOCH], int),
            version=convert(hdr[rpmt.RPMTAG_VERSION]),
            release=convert(hdr[rpmt.RPMTAG_RELEASE]),
            arch=detect_arch(hdr),
            disttag=convert(hdr[rpmt.RPMTAG_DISTTAG]),
            is_srpm=bool(hdr[rpmt.RPMTAG_SOURCEPACKAGE]),
            buildtime=convert(hdr[rpmt.RPMTAG_BUILDTIME]),
        )
        return pkg
