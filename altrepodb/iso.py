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

import os
import json
import shutil
import tempfile
import datetime
from dataclasses import asdict, dataclass
from collections import namedtuple
from typing import Any, Union
from pathlib import Path
from uuid import uuid4

from .repo import PackageSetHandler
from .base import File, Package, ISOProcessorConfig, DEFAULT_LOGGER, PkgHash, PackageSet
from .rpmdb import RPMDBPackages, RPMDBOpenError
from .logger import LoggerProtocol, _LoggerOptional
from .exceptions import (
    RunCommandError,
    ImageMounterMountError,
    ImageMounterUnmountError,
    ImageMounterImageTypeError,
    ImageMounterRunCommandError,
    ISOImageOpenError,
    ISOProcessingError,
    ISOImageInvalidError,
    ISOProcessingGuessBranchError,
    ISOProcessingBranchMismatchError,
    ISOProcessingPackageNotInDBError,
    ISOProcessingExecutableNotFoundError,
)
from .utils import (
    mmhash,
    run_command,
    snowflake_id_sqfs,
    md5_from_file,
    sha1_from_file,
    cvt_ts_to_datetime,
)
from .database import DatabaseClient


#  custom types
_StringOrPath = Union[str, Path]


@dataclass
class ImageMounter:
    name: str
    type: str
    path: str
    ismount: bool
    _log: LoggerProtocol
    _tmpdir: tempfile.TemporaryDirectory
    _image_path: str

    def __init__(
        self,
        image_name: str,
        image_path: str,
        image_type: str,
        logger: _LoggerOptional = None,
    ):
        if logger is not None:
            self._log = logger
        else:
            self._log = DEFAULT_LOGGER(name="ImageMounter")

        self.name = image_name
        self.type = image_type

        if image_type not in ("iso", "squashfs"):
            self._log.error(f"Unsupported filesystem image type {image_type}")
            raise ImageMounterImageTypeError(self.name, self.type)

        self._image_path = image_path
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path = self._tmpdir.name
        self.ismount = False

    def _run_command(self, *args):
        try:
            _, _, _, _ = run_command(
                *args, raise_on_error=True, logger=self._log, timeout=10
            )
        except RunCommandError as e:
            raise ImageMounterRunCommandError("Subprocess returned an error") from e

    def _unmount(self, path: str) -> None:
        self._log.info(f"Unmounting {path}...")
        try:
            self._run_command("umount", path)
        except ImageMounterRunCommandError as e:
            raise ImageMounterUnmountError(self._image_path, self.path) from e

    def _mount_iso(self, iso_path: str, mount_path: str) -> None:
        self._log.info(f"Mounting ISO image {iso_path} to {mount_path}")
        try:
            self._run_command("fuseiso", iso_path, mount_path)
        except ImageMounterRunCommandError as e:
            raise ImageMounterMountError(self._image_path, self.path) from e

    def _mount_sqfs(self, iso_path: str, mount_path: str) -> None:
        self._log.info(f"Mounting SquashFS image {iso_path} to {mount_path}")
        try:
            self._run_command("squashfuse", iso_path, mount_path)
        except ImageMounterRunCommandError as e:
            raise ImageMounterMountError(self._image_path, self.path) from e

    def open(self):
        if not self.ismount:
            try:
                if self.type == "iso":
                    self._mount_iso(self._image_path, self.path)
                elif self.type == "squashfs":
                    self._mount_sqfs(self._image_path, self.path)
                else:
                    self._log.error(f"Unsupported filesystem image type {self.type}")
                    raise ImageMounterImageTypeError(self.name, self.type)
                self.ismount = True
            except Exception as e:
                self._log.error(
                    f"Failed to mount {self.type} image {self._image_path} to {self.path}"
                )
                self._tmpdir.cleanup()
                raise e

    def close(self):
        if self.ismount:
            try:
                self._unmount(self.path)
            except Exception as e:
                self._log.error(f"Failed to mount {self.type} image at {self.path}")
                raise e
            finally:
                self.ismount = False
            self._tmpdir.cleanup()


@dataclass
class SquashFSImageMeta:
    hash: int
    sha1: bytes
    size: int
    mtime: int


@dataclass
class SquashFSImage:
    name: str
    meta: SquashFSImageMeta
    files: list[File]
    packages: list[Package]
    mount: ImageMounter


@dataclass
class ISOImageMeta:
    arch: str
    date: str
    info: str
    commit: str
    isoinfo: str


@dataclass
class ISOImage:
    name: str
    path: str
    size: int
    meta: ISOImageMeta
    mount: ImageMounter
    packages: list[Package]


@dataclass
class ImageMeta:
    arch: str
    date: datetime.datetime
    file: str
    branch: str
    edition: str
    variant: str
    release: str
    version_major: int
    version_minor: int
    version_sub: int
    image_type: str


def stringify_image_meta(meta: ImageMeta) -> str:
    """Return image meta information class as string JSON dump."""

    return json.dumps({k: str(v) for k, v in asdict(meta).items()})


class ISO:
    def __init__(
        self, iso_name: str, iso_path: _StringOrPath, logger: _LoggerOptional = None
    ) -> None:
        self._parsed = False
        if logger is not None:
            self.logger = logger
        else:
            self.logger = DEFAULT_LOGGER(name="ISO")
        self.iso_name = iso_name
        self.iso_path = str(iso_path)
        self._sqfs: list[SquashFSImage] = []
        self._iso = ISOImage(
            name=self.iso_name,
            path=self.iso_path,
            meta=ISOImageMeta(
                arch="",
                date="",
                info="",
                commit="",
                isoinfo="",
            ),
            size=Path(self.iso_path).stat().st_size,
            mount=ImageMounter("ISO", self.iso_path, "iso", self.logger),
            packages=[],
        )

    def _close(self) -> None:
        self.logger.info(f"Closing {self._iso.name} ISO image")
        for sqfs in self._sqfs:
            if sqfs.mount.ismount:
                sqfs.mount.close()
        if self._iso.mount.ismount:
            self._iso.mount.close()

    def _check_system_executables(self):
        not_found_ = []
        for executable in (
            "umount",
            "isoinfo",
            "fuseiso",
            "squashfuse",
        ):
            if shutil.which(executable) is None:
                self.logger.error(f"Executable '{executable}' not found")
                not_found_.append(executable)
        if not_found_:
            not_found_ = ", ".join(not_found_)
            raise ISOProcessingExecutableNotFoundError(not_found_)

    def _open_iso(self) -> None:
        """Open ISO image for file processing."""

        if not os.path.isfile(self._iso.path):
            self.logger.error(f"{self._iso.path} is not an ISO image")
            raise ISOImageInvalidError(self._iso.path)

        try:
            self.logger.info(f"Opening {self._iso.name} ISO image")
            self._iso.mount.open()
        except Exception as e:
            self.logger.error(f"Failed to mount ISO image {self._iso.path}")
            raise ISOImageOpenError(self._iso.path) from e

        self.logger.info(f"Processing SquashFS images from ISO")
        for sqfs_name in ("live", "rescue", "altinst"):
            sqfs_path = os.path.join(self._iso.mount.path, sqfs_name)
            if os.path.isfile(sqfs_path):
                self.logger.info(
                    f"Found '{sqfs_name}' SquashFS image in {self._iso.name}"
                )
                sqfs = SquashFSImage(
                    name=sqfs_name,
                    meta=SquashFSImageMeta(
                        hash=0,
                        sha1=b"",
                        size=os.stat(sqfs_path).st_size,
                        mtime=int(os.stat(sqfs_path).st_mtime),
                    ),
                    files=[],
                    packages=[],
                    mount=ImageMounter(sqfs_name, sqfs_path, "squashfs", self.logger),
                )
                try:
                    self.logger.info(f"Opening '{sqfs_name}' SquashFS image")
                    sqfs.mount.open()
                    self._sqfs.append(sqfs)
                except Exception as e:
                    self.logger.error(f"Failed to mount '{sqfs_name}' SquashFS image")
                    raise ISOImageOpenError(self._iso.path) from e

    def _get_uid_gid_lut(self, path: Path) -> tuple[dict[int, str], dict[int, str]]:
        def parse_file(content: str) -> dict[int, str]:
            res = {}
            for line in content.split("\n"):
                l = line.split(":")
                if len(l) > 2:
                    res[int(l[2])] = l[0]
            return res

        uid = parse_file(path.joinpath("etc/passwd").read_text())
        gid = parse_file(path.joinpath("etc/group").read_text())
        return uid, gid

    def _get_file_info(
        self,
        file: Path,
        uid_lut: dict[int, str],
        gid_lut: dict[int, str],
    ) -> File:
        md5_ = b""
        link_ = ""
        class_ = "file"
        if file.is_symlink():
            stat_ = file.lstat()
            link_ = str(file.readlink())
            class_ = "symlink"
        else:
            stat_ = file.stat()
            try:
                md5_ = md5_from_file(file, as_bytes=True)
            except Exception as e:
                self.logger.info(
                    f"Failed to calculate MD5 checksum for file : {str(file.relative_to(Path.cwd()))}"
                )
        file_ = File(
            md5=md5_,  # type: ignore
            # restored file name as it would appear from FS root
            name="/" + str(Path(file).relative_to(Path.cwd())),
            size=stat_.st_size,
            linkto=link_,
            # flag=0,  # XXX: st_flags not supported
            # lang="",  # TODO: get whatever suitable here
            mode=stat_.st_mode,
            rdev=stat_.st_rdev,
            mtime=int(stat_.st_mtime),
            class_=class_,
            device=stat_.st_dev,
            username=uid_lut.get(stat_.st_uid, ""),
            groupname=gid_lut.get(stat_.st_gid, ""),
            # verifyflag=0,  # TODO: get xattrs as UInt32 value somehow
        )
        return file_

    def _process_iso(self):
        # read ISO image meta information
        self.logger.info(f"Gathering ISO image meta information")
        for file in [
            f
            for f in Path(self._iso.mount.path).joinpath(".disk").iterdir()
            if f.is_file()
        ]:
            self._iso.meta.__setattr__(file.name, file.read_text().rstrip("\n"))
        _, out, _, errcode = run_command(
            "isoinfo",
            "-d",
            "-i",
            self._iso.path,
            raise_on_error=False,
            logger=self.logger,
        )
        if errcode == 0:
            self._iso.meta.isoinfo = out
        self.logger.debug(f"ISO image meta information: {self._iso.meta}")
        # parse ISO image packages
        self.logger.info(f"Gathering ISO image RPM packages information")
        iso_rpms_dir = Path(self._iso.mount.path).joinpath("ALTLinux")
        if iso_rpms_dir.is_dir():
            for pkg in (
                p
                for p in iso_rpms_dir.joinpath("RPMS.main").iterdir()
                if p.is_file() and p.name.endswith(".rpm")
            ):
                self._iso.packages.append(RPMDBPackages.get_package_info(pkg))
        self.logger.info(
            f"Collected {len(self._iso.packages)} RPM packages from {self.iso_path}/ALTLinux/RPMS.main"
        )

    def _process_squashfs(self):
        self.logger.info(f"Gathering SquashFS images meta information")
        # save CWD
        cwd_ = Path.cwd()
        for sqfs in self._sqfs:
            self.logger.info(f"Processing '{sqfs.name}' SquashFS image")
            # get SquashFS meta information
            self.logger.debug(f"Calculate SquashFs image SHA1 checksum")
            sqfs.meta.sha1 = sha1_from_file(Path(self._iso.mount.path).joinpath(sqfs.name), as_bytes=True)  # type: ignore
            sqfs.meta.hash = snowflake_id_sqfs(mtime=sqfs.meta.mtime, sha1=sqfs.meta.sha1, size=sqfs.meta.size)  # type: ignore
            # parse SquashFS images packages and files
            self.logger.debug(f"Reading SquashFs image RPM packages")
            try:
                rpmdb = RPMDBPackages(
                    str(Path(sqfs.mount.path).joinpath("var/lib/rpm"))
                )
                sqfs.packages = rpmdb.packages_list
                self.logger.info(
                    f"Collected {rpmdb.count} RPM packages from '{sqfs.name}' SquashFS image"
                )
            except RPMDBOpenError:
                self.logger.info(
                    f"No RPM packages found in '{sqfs.name}' SquashFS image"
                )
            if not sqfs.packages:
                self.logger.info(f"Collecting SquashFS image files information")
                # change dir to mounted SquashFS to handle symlink resolving
                os.chdir(sqfs.mount.path)
                # get uid and gid lookup tables from /etc/passwd and /etc/groups files
                uid_lut, guid_lut = self._get_uid_gid_lut(Path.cwd())
                for file in (
                    f for f in Path(sqfs.mount.path).rglob("*") if not f.is_dir()
                ):
                    sqfs.files.append(
                        self._get_file_info(
                            file=file,
                            uid_lut=uid_lut,
                            gid_lut=guid_lut,
                        )
                    )
                self.logger.info(
                    f"Collected {len(sqfs.files)} files from '{sqfs.name}' SquashFS image"
                )
        # restore work directory
        os.chdir(cwd_)

    def run(self):
        self.logger.info(f"Processing {self._iso.name} ISO image")
        self._check_system_executables()
        try:
            self._open_iso()
            self._process_iso()
            self._process_squashfs()
            self._parsed = True
        except ISOProcessingError:
            self.logger.error(
                f"Error occured while processing ISO image", exc_info=True
            )
            raise
        finally:
            self._close()

    @property
    def iso(self) -> ISOImage:
        if not self._parsed:
            self.run()
        return self._iso

    @property
    def sqfs(self) -> list[SquashFSImage]:
        if not self._parsed:
            self.run()
        return self._sqfs


@dataclass
class SQL:
    create_tmp_table = """
CREATE TEMPORARY TABLE {tmp_table} {columns}
"""

    select_all_tmp_table = """
SELECT * FROM {tmp_table}
"""

    truncate_tmp_table = """
TRUNCATE TABLE {tmp_table}
"""

    insert_into_tmp_table = """
INSERT INTO {tmp_table} (*) VALUES
"""

    drop_tmp_table = """
DROP TABLE {tmp_table}
"""

    get_branch_by_packages = """
SELECT
    pkgset_name,
    count(pkg_hash) AS cnt
FROM static_last_packages
WHERE pkg_sourcepackage = 0
    AND pkgset_name NOT LIKE '%:%'
    AND pkg_hash IN (
        SELECT * FROM {tmp_table}
    )
GROUP BY pkgset_name
ORDER BY cnt DESC
"""

    get_branch_date_by_packages = """
WITH
PkgsetRoots AS
(
    SELECT pkgset_uuid, pkgset_date
    FROM PackageSetName
    WHERE pkgset_depth = 0
        AND pkgset_nodename = '{branch}'
),
PkgsetUUIDs AS
(
    SELECT pkgset_uuid, R.pkgset_date AS pdate, R.pkgset_uuid AS ruuid
    FROM PackageSetName
    LEFT JOIN
    (
        SELECT pkgset_date, pkgset_uuid FROM PkgsetRoots
    ) AS R ON R.pkgset_uuid = PackageSetName.pkgset_ruuid
    WHERE pkgset_depth = 2
        AND pkgset_ruuid IN
        (
            SELECT pkgset_uuid FROM PkgsetRoots
        )
),
(
    SELECT argMax(uuid, (cnt, date))
    FROM
    (
        SELECT
            PU.ruuid AS uuid, PU.pdate AS date, countDistinct(pkg_hash) AS cnt
        FROM PackageSet
        INNER JOIN
        (
            SELECT pkgset_uuid, pdate, ruuid
            FROM PkgsetUUIDs
        ) AS PU USING pkgset_uuid
        WHERE pkgset_uuid IN (select pkgset_uuid FROM PkgsetUUIDs)
            AND pkg_hash IN (select pkg_hash FROM {tmp_table})
        GROUP BY uuid, date
        ORDER BY cnt DESC, date DESC
    )
) AS branch_ruuid
SELECT pkgset_nodename, toString(pkgset_date)
FROM PackageSetName
WHERE pkgset_uuid = branch_ruuid
"""

    get_tmp_pkgs_by_files = """
CREATE TEMPORARY TABLE {tmp_table1} AS(
    WITH
    PkgsByFiles AS
    (
        SELECT DISTINCT pkg_hash
        FROM Files
        WHERE (file_hashname, file_md5) IN (
            SELECT
                file_hashname,
                file_md5
            FROM {tmp_table2}
        )
    ),
    PkgsetRoots AS
    (
        SELECT pkgset_uuid, pkgset_date
        FROM PackageSetName
        WHERE pkgset_depth = 0
            AND pkgset_nodename = '{branch}'
    ),
    PkgsetUUIDs AS
    (
        SELECT pkgset_uuid, R.pkgset_date AS pdate, R.pkgset_uuid AS ruuid
        FROM PackageSetName
        LEFT JOIN
        (
            SELECT pkgset_date, pkgset_uuid FROM PkgsetRoots
        ) AS R ON R.pkgset_uuid = PackageSetName.pkgset_ruuid
        WHERE pkgset_depth = 2
            AND pkgset_ruuid IN
            (
                SELECT pkgset_uuid FROM PkgsetRoots
            )
    ),
    (
        SELECT argMax(uuid, (cnt, date))
        FROM
        (
            SELECT
                PU.ruuid AS uuid, PU.pdate AS date, countDistinct(pkg_hash) AS cnt
            FROM PackageSet
            INNER JOIN
            (
                SELECT pkgset_uuid, pdate, ruuid
                FROM PkgsetUUIDs
            ) AS PU USING pkgset_uuid
            WHERE pkgset_uuid IN (select pkgset_uuid FROM PkgsetUUIDs)
                AND pkg_hash IN (select pkg_hash FROM PkgsByFiles)
            GROUP BY uuid, date
            ORDER BY cnt DESC, date DESC
        )
    ) AS branch_ruuid
    SELECT pkg_hash
    FROM PkgsByFiles
    WHERE pkg_hash IN
    (
        SELECT pkg_hash
        FROM PackageSet
        WHERE pkgset_uuid IN
        (
            SELECT pkgset_uuid FROM PkgsetUUIDs WHERE ruuid = branch_ruuid
        )
    )
)
"""

    get_tmp_orphan_files = """
SELECT * FROM {tmp_table1}
WHERE (file_hashname, file_md5) NOT IN
(
    SELECT file_hashname, file_md5
    FROM Files
    WHERE file_class = 'file'
        AND pkg_hash IN
        (
            SELECT pkg_hash FROM {tmp_table2}
        )
)
"""

    get_packages_info = """
SELECT
    pkg_hash,
    pkg_name,
    pkg_arch,
    pkg_epoch,
    pkg_version,
    pkg_release,
    pkg_disttag,
    pkg_buildtime
FROM Packages
WHERE pkg_hash IN
(
    SELECT pkg_hash FROM {tmp_table}
)
"""

    get_pkgs_not_in_db = """
WITH
PkgsInDB AS
(
    SELECT pkg_hash
    FROM Packages
    WHERE pkg_hash IN
    (
        SELECT * FROM {tmp_table}
    )
)
SELECT DISTINCT pkg_hash
FROM {tmp_table}
WHERE pkg_hash NOT IN
(
    SELECT * FROM PkgsInDB
)
"""

    insert_files = """
INSERT INTO Files_insert (*) VALUES
"""

    insert_package = """
INSERT INTO Packages_buffer (*) VALUES
"""

    insert_package_hashes = """
INSERT INTO PackageHash_buffer (*) VALUES
"""


class ISOProcessor:
    def __init__(self, config: ISOProcessorConfig, image_meta: ImageMeta) -> None:
        self.config = config
        self.meta = image_meta
        self.sql = SQL()
        self.name = self._build_iso_name()

        if self.config.logger is not None:
            self.logger = self.config.logger
        else:
            self.logger = DEFAULT_LOGGER(name="iso")

        if self.config.debug:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        self.conn = DatabaseClient(config=self.config.dbconfig, logger=self.logger)
        self.iso = ISO(
            iso_name=self.meta.file, iso_path=self.config.path, logger=self.logger
        )

    def _build_iso_name(self) -> str:
        return ":".join(
            (
                self.meta.branch,
                self.meta.edition,
                ".".join(
                    (
                        self.meta.release,
                        str(self.meta.version_major),
                        str(self.meta.version_minor),
                        str(self.meta.version_sub),
                    )
                ),
                self.meta.arch,
                self.meta.variant,
                self.meta.image_type,
            )
        )

    def _find_base_repo(self, packages: list[Package]) -> tuple[str, str]:
        # find base branch by packages list
        # 1. create temporary table
        tmp_table = "_tmpPkgs"
        res = self.conn.execute(
            self.sql.create_tmp_table.format(
                tmp_table=tmp_table, columns="(pkg_hash UInt64)"
            )
        )
        # 2. insert package hashes
        res = self.conn.execute(
            self.sql.insert_into_tmp_table.format(tmp_table=tmp_table),
            ({"pkg_hash": p.hash} for p in packages),
        )
        # 3. get most likely base branch from last package sets
        res = self.conn.execute(
            self.sql.get_branch_by_packages.format(tmp_table=tmp_table)
        )
        if res:
            self.logger.info(
                f"Most likely branch from latest package sets: {res[0][0]}"
            )
        self.logger.debug(
            f"Top 3 latest package sets matching by {len(packages)} packages: "
            + "; ".join([f"{r[0]} [{r[1]}]" for i, r in enumerate(res) if i < 3])
        )
        # 4. get most likely branch date by packages list
        res = self.conn.execute(
            self.sql.get_branch_date_by_packages.format(
                tmp_table=tmp_table, branch=self.meta.branch
            )
        )
        if not res:
            raise ISOProcessingGuessBranchError
        branch, date = res[0]
        # 5. cleaun-up
        res = self.conn.execute(self.sql.drop_tmp_table.format(tmp_table=tmp_table))
        return branch, date

    def _check_packages_in_db(self, packages: list[Package]) -> list[Package]:
        # check if packages is in database
        not_found: list[Package] = []
        # 1. create temporary table
        tmp_table = "_tmpPkgs"
        res = self.conn.execute(
            self.sql.create_tmp_table.format(
                tmp_table=tmp_table, columns="(pkg_hash UInt64)"
            )
        )
        # 2. insert package hashes
        res = self.conn.execute(
            self.sql.insert_into_tmp_table.format(tmp_table=tmp_table),
            ({"pkg_hash": p.hash} for p in packages),
        )
        # 3. get packages not found in DB
        res = self.conn.execute(self.sql.get_pkgs_not_in_db.format(tmp_table=tmp_table))
        not_found_ = {r[0] for r in res}
        if not_found_:
            for p in packages:
                # skip SquashFS meta packages
                if p.hash in not_found_ and "_orphaned-files_" not in p.name:
                    not_found.append(p)
        # 4. cleaun-up
        res = self.conn.execute(self.sql.drop_tmp_table.format(tmp_table=tmp_table))

        return not_found

    def _find_packages_from_files(
        self, sqfs: SquashFSImage, branch: str = ""
    ) -> tuple[list[Package], list[File]]:
        # find packages by files using branch constraint and orphaned files
        packages: list[Package] = []
        orphan_files: list[File] = []

        if branch == "":
            branch = self.meta.branch

        # 1. create temporary table
        tmp_files = "_tmpFiles"
        res = self.conn.execute(
            self.sql.create_tmp_table.format(
                tmp_table=tmp_files,
                columns="(file_hashname UInt64, file_md5 FixedString(16))",
            )
        )
        # 2. insert package hashes
        res = self.conn.execute(
            self.sql.insert_into_tmp_table.format(tmp_table=tmp_files),
            ({"file_hashname": mmhash(f.name), "file_md5": f.md5} for f in sqfs.files),
            settings={"strings_as_bytes": True},
        )
        # 3. create tmp table with packages by files
        tmp_packages = "_tmpPackages"
        res = self.conn.execute(
            self.sql.get_tmp_pkgs_by_files.format(
                tmp_table1=tmp_packages, tmp_table2=tmp_files, branch=branch
            )
        )
        # 4. get found packages
        res = self.conn.execute(
            self.sql.get_packages_info.format(tmp_table=tmp_packages)
        )
        for r in res:
            packages.append(
                Package(
                    hash=r[0],
                    name=r[1],
                    arch=r[2],
                    epoch=r[3],
                    version=r[4],
                    release=r[5],
                    disttag=r[6],
                    buildtime=r[7],
                )
            )

        # 5. get orphaned files
        res = self.conn.execute(
            self.sql.get_tmp_orphan_files.format(
                tmp_table1=tmp_files, tmp_table2=tmp_packages
            )
        )
        files_md5 = {r[1] for r in res}

        orphan_files = [f for f in sqfs.files if f.md5 in files_md5]

        return packages, orphan_files

    def _process_squashfs_files(
        self, sqfs: SquashFSImage, branch: str = ""
    ) -> tuple[Package, list[File]]:
        """Builds metapackage with orphaned files and updates SquashFS object packages and files."""

        # 1. get packages and orphaned files for SquashFS image
        packages, orphan_files = self._find_packages_from_files(
            sqfs=sqfs, branch=branch
        )
        self.logger.info(
            f"Found {len(packages)} packages for '{sqfs.name}' SquashFS image"
        )
        self.logger.info(
            f"Found {len(orphan_files)} orphaned files in '{sqfs.name}' SquashFS image"
        )
        # 2. make metapackage
        iso_name_ = self.meta.file
        iso_date_ = self.meta.date.strftime("%Y%m%d")
        iso_date_ = self.iso.iso.meta.date or iso_date_
        orphan_package = Package(
            hash=sqfs.meta.hash,
            name=f"{sqfs.name}_orphaned-files_{iso_name_}_{iso_date_}",
            arch=self.iso.iso.meta.arch,
            buildtime=sqfs.meta.mtime,
            is_srpm=False,
        )
        self.logger.info(
            f"Built '{orphan_package.name}' metapackage for orphaned files in '{sqfs.name}' image"
        )
        # 3. update SquashFS object
        sqfs.files = orphan_files
        sqfs.packages = packages
        sqfs.packages.append(orphan_package)

        return orphan_package, orphan_files

    def _store_metapackage(
        self, sqfs: SquashFSImage, package: Package, files: list[File]
    ) -> None:
        # store SquashFS metapackage for orphaned files
        # files for metapackage are stored too
        # 1. make package hashes
        pkg_hash = PkgHash(
            sf=sqfs.meta.hash, md5=b"", sha1=sqfs.meta.sha1, sha256=b"", blake2b=b""
        )
        # 2. store orphaned files
        files_list: list[dict[str, Any]] = []
        DBFile = namedtuple(
            "DBFile",
            [
                "pkg_hash",
                "file_name",
                "file_linkto",
                "file_md5",
                "file_size",
                "file_mode",
                "file_rdev",
                "file_mtime",
                "file_flag",
                "file_username",
                "file_groupname",
                "file_verifyflag",
                "file_device",
                "file_lang",
                "file_class",
            ],
        )
        if not self.config.dryrun:
            for file in files:
                files_list.append(
                    DBFile(
                        pkg_hash=pkg_hash.sf,
                        file_name=file.name,
                        file_md5=file.md5,
                        file_flag=file.flag,
                        file_lang=file.lang,
                        file_mode=file.mode,
                        file_rdev=file.rdev,
                        file_size=file.size,
                        file_class=file.class_,
                        file_mtime=file.mtime,
                        file_device=file.device,
                        file_linkto=file.linkto,
                        file_username=file.username,
                        file_groupname=file.groupname,
                        file_verifyflag=file.verifyflag,
                    )._asdict()
                )
            res = self.conn.execute(self.sql.insert_files, files_list)
            self.logger.info(
                f"{len(files_list)} files inserted for package {package.name}"
            )
        else:
            self.logger.info(
                f"Found {len(files)} files to be inserted for package {package.name}"
            )
        # 3. store metapackage
        pkg_ = {
            "pkg_hash": sqfs.meta.hash,
            "pkg_cs": sqfs.meta.sha1,
            "pkg_packager": "ISO Loader",
            "pkg_packager_email": "iso_loader@altlinux.org",
            "pkg_name": package.name,
            "pkg_arch": package.arch,
            "pkg_version": "",
            "pkg_release": "",
            "pkg_epoch": 0,
            "pkg_serial_": 0,
            "pkg_buildtime": package.buildtime,
            "pkg_buildhost": "",
            "pkg_size": sqfs.meta.size,
            "pkg_archivesize": sqfs.meta.size,
            "pkg_filesize": sqfs.meta.size,
            "pkg_rpmversion": "",
            "pkg_cookie": "",
            "pkg_sourcepackage": 0,
            "pkg_disttag": package.disttag,
            "pkg_sourcerpm": sqfs.name,
            "pkg_srcrpm_hash": 0,
            "pkg_filename": package.name,
            "pkg_complete": 1,
            "pkg_summary": f"Metapackage for orphaned files from '{sqfs.name}' SquashFS image",
            "pkg_description": (
                f"Metapackage for orphaned files from '{sqfs.name}' "
                f"SquashFS image from '{self.meta.file}' ISO image"
            ),
            "pkg_changelog.date": [],
            "pkg_changelog.name": [],
            "pkg_changelog.evr": [],
            "pkg_changelog.hash": [],
            "pkg_distribution": f"ALT {self.meta.branch}",
            "pkg_vendor": "BASEALT LTD",
            "pkg_gif": "",
            "pkg_xpm": "",
            "pkg_license": "",
            "pkg_group_": "Other",
            "pkg_url": "",
            "pkg_os": "ALT Linux",
            "pkg_prein": "",
            "pkg_postin": "",
            "pkg_preun": "",
            "pkg_postun": "",
            "pkg_icon": "",
            "pkg_preinprog": [],
            "pkg_postinprog": [],
            "pkg_preunprog": [],
            "pkg_postunprog": [],
            "pkg_buildarchs": [],
            "pkg_verifyscript": "",
            "pkg_verifyscriptprog": [],
            "pkg_prefixes": [],
            "pkg_instprefixes": [],
            "pkg_optflags": "",
            "pkg_disturl": "",
            "pkg_payloadformat": "",
            "pkg_payloadcompressor": "",
            "pkg_payloadflags": "",
            "pkg_platform": "",
        }
        if not self.config.dryrun:
            # store package
            res = self.conn.execute(self.sql.insert_package, [pkg_])
            # store package hashes
            res = self.conn.execute(
                self.sql.insert_package_hashes,
                [
                    {
                        "pkgh_mmh": pkg_hash.sf,
                        "pkgh_md5": pkg_hash.md5,
                        "pkgh_sha1": pkg_hash.sha1,
                        "pkgh_sha256": pkg_hash.sha256,
                        "pkgh_blake2b": pkg_hash.blake2b,
                    }
                ],
            )
            self.logger.info(
                f"Metapackage '{package.name}' for SquashFS '{sqfs.name}' inserted to DB"
            )

    def _make_iso_pkgset(self) -> list[PackageSet]:
        # build packageset structure from ISO image for PackageSetName table
        # depth 0: root: ISO itself with meta information in 'pkgset_kv' fields
        # depth 1: 'rpms': RPM packages found at ISO itself if any
        # depth 1: '%sqfs.name': for SquashFS images
        iso_pkgsets: list[PackageSet] = []
        # 1. packageset root
        ruuid_ = str(uuid4())
        root = PackageSet(
            name=self.name,
            uuid=ruuid_,
            puuid="00000000-0000-0000-0000-000000000000",
            ruuid=ruuid_,
            date=self.meta.date,
            depth=0,
            complete=1,
            tag=self.name,
            kw_args={
                "type": "iso",
                "size": str(self.iso.iso.size),
                "class": "iso",
                "branch": self.meta.branch,
            },
            package_hashes=[],
        )
        root.kw_args.update(asdict(self.iso.iso.meta))
        root.kw_args.update({"json": stringify_image_meta(self.meta)})
        iso_pkgsets.append(root)
        self.logger.debug(f"PackageSet root {root}")
        # 2. ISO image RPM packages
        if self.iso.iso.packages:
            rpms = PackageSet(
                name="rpms",
                uuid=str(uuid4()),
                puuid=root.uuid,
                ruuid=root.uuid,
                date=root.date,
                depth=1,
                complete=1,
                tag=root.tag,
                kw_args={
                    "type": "rpms",
                    "size": str(len(self.iso.iso.packages)),
                    "class": "iso",
                    "branch": self.meta.branch,
                },
                package_hashes=[p.hash for p in self.iso.iso.packages],
            )
            iso_pkgsets.append(rpms)
        # 3. SquashFS images
        for sqfs in self.iso.sqfs:
            pkgset = PackageSet(
                name=sqfs.name,
                uuid=str(uuid4()),
                puuid=root.uuid,
                ruuid=root.uuid,
                date=root.date,
                depth=1,
                complete=1,
                tag=root.tag,
                kw_args={
                    "type": "squashfs",
                    "size": str(len(sqfs.packages)),
                    "class": "iso",
                    "branch": self.meta.branch,
                },
                package_hashes=[p.hash for p in sqfs.packages],
            )
            pkgset.kw_args.update(
                {
                    "hash": str(sqfs.meta.hash),
                    "sha1": sqfs.meta.sha1.hex(),
                    "image_size": str(sqfs.meta.size),
                    "orphaned_files": str(len(sqfs.files)),
                    "mtime": cvt_ts_to_datetime(sqfs.meta.mtime).isoformat(),
                }
            )
            iso_pkgsets.append(pkgset)
        return iso_pkgsets

    def _store_iso_pkgset(self, pkgsets: list[PackageSet]) -> None:
        # store ISO image pkgset
        psh = PackageSetHandler(conn=self.conn, logger=self.logger)
        # load ISO package set components from leaves to root
        for pkgset in reversed(pkgsets):
            psn = asdict(pkgset)
            del psn["package_hashes"]
            if not self.config.dryrun:
                self.logger.info(
                    f"Inserting package set records for '{pkgset.name}' into database"
                )
                # 1. store PackageSetName record
                psh.insert_pkgset_name(**psn)
                # 2. store PackageSet record
                if pkgset.package_hashes:
                    psh.insert_pkgset(pkgset.uuid, pkgset.package_hashes)

    def _check_iso_date_name_in_db(
        self, iso_name: str, pkgset_date: datetime.date
    ) -> bool:
        result = self.conn.execute(
            f"SELECT COUNT(*) FROM PackageSetName WHERE "
            f"pkgset_nodename='{iso_name}' AND pkgset_date='{pkgset_date}'"
        )
        return result[0][0] != 0  # type: ignore

    def run(self) -> None:
        # -1. check if ISO is already loaded to DB
        if not self.config.force:
            if self._check_iso_date_name_in_db(self.name, self.meta.date):
                self.logger.info(f"ISO image '{self.name}' already exists in database")
                if not self.config.dryrun:
                    return
        # 0. mount and parse ISO image
        self.iso.run()
        self.logger.info(f"ISO info:\n{self.iso.iso.meta.isoinfo}")
        # 1. check ISO packages in branch
        missing: list[Package] = []

        if self.iso.iso.packages:
            # 1.1 check branch mismatching
            self.logger.info(f"Checking ISO image '{self.iso.iso.name}' branch")
            branch, date = self._find_base_repo(self.iso.iso.packages)
            self.logger.info(
                f"Most likely branch for '{self.iso.iso.name}' is '{branch}' on '{date}'"
            )
            #  1.2 check all RPM packages in database
            self.logger.info(f"Checking ISO image '{self.iso.iso.name}' packages")
            missing = self._check_packages_in_db(self.iso.iso.packages)
            if missing:
                self.logger.error(
                    f"{len(missing)} packages not found in database\n"
                    + "\n".join(
                        [
                            f"[{p.hash}] {p.name}-{p.version}-{p.release} {p.arch}"
                            for p in missing
                        ]
                    )
                )
                self.logger.debug(
                    f"Packages not found in database:\n{[p for p in missing]}"
                )
                if not self.config.dryrun or self.config.force:
                    raise ISOProcessingPackageNotInDBError(missing=missing)
        # 2. Proceed with SquashFS images without packages
        for sqfs in self.iso.sqfs:
            if sqfs.packages or not sqfs.files:
                continue
            self.logger.info(f"Processing SquashFS image '{sqfs.name}' files")
            o_package, o_files = self._process_squashfs_files(sqfs)
            self._store_metapackage(sqfs, o_package, o_files)
        # 3. check SquashFS packages consistency
        for sqfs in self.iso.sqfs:
            if not sqfs.packages:
                continue
            # 3.1 check branch mismatching
            self.logger.info(f"Checking SquashFS image '{sqfs.name}' branch")
            branch, date = self._find_base_repo(sqfs.packages)
            self.logger.info(
                f"Most likely branch for '{sqfs.name}' is '{branch}' on '{date}'"
            )
            # 3.2 check all RPM packages in database
            missing = []
            self.logger.info(f"Checking SquashFS image '{sqfs.name}' packages")
            missing = self._check_packages_in_db(sqfs.packages)
            if missing:
                self.logger.error(
                    f"{len(missing)} packages not found in database\n"
                    + "\n".join([p.name for p in missing])
                )
                if not self.config.dryrun or self.config.force:
                    raise ISOProcessingPackageNotInDBError(missing=missing)
        # 4. build and store ISO image pkgset
        self._store_iso_pkgset(self._make_iso_pkgset())
