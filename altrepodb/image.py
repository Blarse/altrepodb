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

from aifc import Error
import os
import shutil
import tarfile
import datetime
import tempfile
import libarchive
from dataclasses import asdict, dataclass
from collections import namedtuple
from typing import Any, Union
from pathlib import Path
from uuid import uuid4

from multiprocessing import Process, Queue

from .repo import PackageSetHandler
from .base import (
    Package,
    ImageMeta,
    PackageSet,
    ImageProcessorConfig,
    DEFAULT_LOGGER,
    stringify_image_meta,
)
from .rpmdb import RPMDBPackages, RPMDBOpenError
from .logger import LoggerProtocol, _LoggerOptional
from .exceptions import (
    RunCommandError,
    ImageMountError,
    ImageUnmountError,
    ImageTypeError,
    ImageRunCommandError,
    ImageOpenError,
    ImageProcessingError,
    ImageInvalidError,
    ImageProcessingGuessBranchError,
    ImageProcessingBranchMismatchError,
    ImageProcessingPackageNotInDBError,
    ImageProcessingExecutableNotFoundError,
)
from .utils import (
    mmhash,
    run_command,
    snowflake_id_sqfs,
    md5_from_file,
    sha1_from_file,
    cvt_ts_to_datetime,
    checksums_from_file,
)
from .database import DatabaseClient


#  custom types
_StringOrPath = Union[str, Path]

# module constants
RUN_COMMAND_TIMEOUT = 30
TAR_RPMDB_PREFIX = "./var/lib/rpm/"
REQUIRED_EXECUTABLES = (
    # "umount",
    # "isoinfo",
    # "fuseiso",
    # "squashfuse",
    "gost12sum",
    "fuserumount",
)


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

        if image_type not in ("img", "tar", "qcow"):
            self._log.error(f"Unsupported filesystem image type {image_type}")
            raise ImageTypeError(self.name, self.type)

        self._image_path = image_path
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path = self._tmpdir.name
        self.ismount = False

    def _run_command(self, *args):
        try:
            _, _, _, _ = run_command(
                *args,
                raise_on_error=True,
                logger=self._log,
                timeout=RUN_COMMAND_TIMEOUT,
            )
        except RunCommandError as e:
            raise ImageRunCommandError("Subprocess returned an error") from e

    def _unmount(self, path: str) -> None:
        self._log.info(f"Unmounting {path}...")
        try:
            if self.type in ("img", "qcow"):
                self._run_command("fuserumount", path)
            else:
                pass
        except ImageRunCommandError as e:
            raise ImageUnmountError(self._image_path, self.path) from e

    def _mount_tar(self, target_path: str, mount_path: str) -> None:
        try:
            self._log.info(f"Mounting TAR archive")
            with libarchive.file_reader(target_path) as arch:
                for entry in arch:
                    # get '/etc/os-release' contents
                    if entry.name.endswith("os-release"):
                        c = b""
                        for b in entry.get_blocks():
                            c += b
                        Path(mount_path).joinpath("os-release").write_text(
                            c.decode("utf-8")
                        )
                    # extract RPMDB files to temporary directory
                    if entry.name.startswith(TAR_RPMDB_PREFIX):
                        self._log.debug(
                            f"Found RPMDB file : {entry.name}, {entry.size}"
                        )
                        if entry.isfile:
                            e_name = entry.name.replace(TAR_RPMDB_PREFIX, "")
                            c = b""
                            with Path(mount_path).joinpath(e_name).open("wb") as f:
                                for b in entry.get_blocks():
                                    f.write(b)
        except Exception as e:
            raise ImageMountError(self._image_path, self.path) from e

    # def _mount_iso(self, iso_path: str, mount_path: str) -> None:
    #     self._log.info(f"Mounting ISO image {iso_path} to {mount_path}")
    #     try:
    #         self._run_command("fuseiso", iso_path, mount_path)
    #     except ImageRunCommandError as e:
    #         raise ImageMountError(self._image_path, self.path) from e

    # def _mount_sqfs(self, iso_path: str, mount_path: str) -> None:
    #     self._log.info(f"Mounting SquashFS image {iso_path} to {mount_path}")
    #     try:
    #         self._run_command("squashfuse", iso_path, mount_path)
    #     except ImageRunCommandError as e:
    #         raise ImageMountError(self._image_path, self.path) from e

    def _mount_img(self, iso_path: str, mount_path: str) -> None:
        pass

    def _mount_qcow(self, iso_path: str, mount_path: str) -> None:
        pass

    def _mount(self, target_path: str, mount_path: str, image_type: str) -> None:
        if image_type == "img":
            self._mount_img(target_path, mount_path)
        elif image_type == "tar":
            self._mount_tar(target_path, mount_path)
        elif image_type == "qcow":
            self._mount_qcow(target_path, mount_path)
        else:
            self._log.error(f"Unsupported filesystem image type {image_type}")
            raise ImageTypeError(self.name, self.type)

    def open(self):
        if not self.ismount:
            try:
                self._mount(self._image_path, self.path, self.type)
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
                self._log.error(f"Failed to unmount {self.type} image at {self.path}")
                raise e
            finally:
                self.ismount = False
            self._tmpdir.cleanup()


@dataclass
class FylesystemImageMeta:
    mtime: datetime.datetime
    md5_cs: str = ""
    sha256_cs: str = ""
    gost12_cs: str = ""
    osrelease: str = ""


@dataclass
class FilesystemImage:
    name: str
    path: str
    size: int
    type: str
    meta: FylesystemImageMeta
    mount: ImageMounter
    packages: list[Package]


class TAR:
    def __init__(
        self, name: str, path: _StringOrPath, logger: _LoggerOptional = None
    ) -> None:
        self._parsed = False
        if logger is not None:
            self.logger = logger
        else:
            self.logger = DEFAULT_LOGGER(name="ISO")
        self.name = name
        self.path = str(path)
        self.p_ = Path(path)
        self._image = FilesystemImage(
            name=self.name,
            path=self.path,
            size=self.p_.stat().st_size,
            type="tar",
            meta=FylesystemImageMeta(mtime=cvt_ts_to_datetime(self.p_.stat().st_mtime)),
            mount=ImageMounter(self.name, self.path, "tar", self.logger),
            packages=list(),
        )

    def _close(self) -> None:
        self.logger.info(f"Closing {self._image.name} image")
        if self._image.mount.ismount:
            self._image.mount.close()

    def _check_system_executables(self):
        not_found_ = []
        for executable in REQUIRED_EXECUTABLES:
            if shutil.which(executable) is None:
                self.logger.error(f"Executable '{executable}' not found")
                not_found_.append(executable)
        if not_found_:
            not_found_ = ", ".join(not_found_)
            raise ImageProcessingExecutableNotFoundError(not_found_)

    def _open_image(self):
        if not tarfile.is_tarfile(self.path):
            self.logger.error(f"{self.path} not a valid TAR file")
            raise ImageInvalidError(self.path)

        try:
            self.logger.info(f"Opening {self.name} filesystem image")
            self._image.mount.open()
        except Exception as e:
            self.logger.error(f"Failed to mount filesystem image {self.path}")
            raise ImageOpenError(self.path) from e

    def _get_checksums(self):
        self.logger.info(f"Calculate MD5, SHA1, SHA256 and GOST12 checksums from file")
        try:
            md5_, sha256_, gost12_ = checksums_from_file(self.path)
            self._image.meta.md5_cs = md5_
            self._image.meta.sha256_cs = sha256_
            self._image.meta.gost12_cs = gost12_
        except Error as e:
            self.logger.error(f"Failed to calculate image checksums")
            raise ImageProcessingError from e

    def _process_image(self):
        # get '/etc/os-release' contents
        p = Path(self._image.mount.path)

        if p.joinpath("os-release").exists():
            self._image.meta.osrelease = p.joinpath("os-release").read_text()
        self.logger.debug(
            f"Image '/etc/os-release' contents: {self._image.meta.osrelease}"
        )

        # read packages from RPMDB
        self.logger.debug(f"Reading filesystem image RPM packages")
        try:
            rpmdb = RPMDBPackages(str(p))
            self._image.packages = rpmdb.packages_list
            self.logger.info(
                f"Collected {rpmdb.count} RPM packages from '{self.name}' filesystem image"
            )
        except RPMDBOpenError:
            self.logger.error(
                f"No RPM packages found in '{self.name}' filesystem image"
            )
            raise ImageProcessingError("No packages found")

    def run(self):
        self.logger.info(f"Processing {self.name} filesystem image")
        try:
            self._check_system_executables()
            self._open_image()
            self._get_checksums()
            self._process_image()
        except ImageProcessingError as e:
            self.logger.error(
                f"Error occured while processing filesystem image", exc_info=True
            )
            raise e
        finally:
            self._close()

    @property
    def image(self) -> FilesystemImage:
        if not self._parsed:
            self.run()
        return self._image


@dataclass(frozen=True)
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


class ImageProcessor:
    def __init__(self, config: ImageProcessorConfig, image_meta: ImageMeta) -> None:
        self.config = config
        self.meta = image_meta
        self.sql = SQL()
        self.tag = self._build_tag()

        if self.config.logger is not None:
            self.logger = self.config.logger
        else:
            self.logger = DEFAULT_LOGGER(name="iso")

        if self.config.debug:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        self.conn = DatabaseClient(config=self.config.dbconfig, logger=self.logger)

        if self.meta.image_type == "tar":
            self.image = TAR(
                name=self.meta.file, path=self.config.path, logger=self.logger
            )
        elif self.meta.image_type == "img":
            # self.image = IMG(
            #     name=self.meta.file, path=self.config.path, logger=self.logger
            # )
            pass
        elif self.meta.image_type == "qcow":
            # self.image = QCOW(
            #     name=self.meta.file, path=self.config.path, logger=self.logger
            # )
            pass
        else:
            self.logger.error(f"Unsupported image type {self.meta.image_type}")
            raise ImageTypeError(self.meta.file, self.meta.image_type)

    def _build_tag(self) -> str:
        return ":".join(
            (
                self.meta.branch,
                self.meta.edition,
                self.meta.flavor,
                self.meta.platform,
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
            raise ImageProcessingGuessBranchError
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

    def _make_image_pkgsets(self) -> list[PackageSet]:
        # build packageset structure from filesystem image for PackageSetName table
        # depth 0: root: image itself with meta information in 'pkgset_kv' fields
        # depth 1: 'rpms': RPM packages found at filesystem image itself
        iso_pkgsets: list[PackageSet] = []
        # 1. packageset root
        ruuid_ = str(uuid4())
        root = PackageSet(
            name=self.meta.edition,
            uuid=ruuid_,
            puuid="00000000-0000-0000-0000-000000000000",
            ruuid=ruuid_,
            date=self.meta.date,
            depth=0,
            complete=1,
            tag=self.tag,
            kw_args={
                "type": self.meta.image_type,
                "size": str(self.image.image.size),
                "class": self.meta.image_type,
                "branch": self.meta.branch,
            },
            package_hashes=[],
        )
        root.kw_args.update(asdict(self.image.image.meta))
        root.kw_args.update(stringify_image_meta(self.meta))
        iso_pkgsets.append(root)
        self.logger.debug(f"PackageSet root {root}")
        # 2. filesystem image RPM packages
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
                "size": str(len(self.image.image.packages)),
                "class": self.meta.image_type,
                "branch": self.meta.branch,
            },
            package_hashes=[p.hash for p in self.image.image.packages],
        )
        iso_pkgsets.append(rpms)

        return iso_pkgsets

    def _store_pkgsets(self, pkgsets: list[PackageSet]) -> None:
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

    def _check_image_tag_date_in_db(
        self, iso_tag: str, pkgset_date: datetime.date
    ) -> bool:
        result = self.conn.execute(
            f"SELECT COUNT(*) FROM PackageSetName WHERE "
            f"pkgset_tag='{iso_tag}' AND pkgset_date='{pkgset_date}'"
        )
        return result[0][0] != 0  # type: ignore

    def run(self) -> None:
        # 1. check if ISO is already loaded to DB
        if not self.config.force:
            if self._check_image_tag_date_in_db(self.tag, self.meta.date):
                self.logger.info(f"ISO image '{self.tag}' already exists in database")
                if not self.config.dryrun:
                    return
        # 2. mount and parse ISO image
        self.image.run()
        self.logger.info(f"Image tag : {self.tag}")
        self.logger.info(f"Image 'os-release' :\n{self.image.image.meta.osrelease}")
        # 3. check ISO packages in branch
        missing: list[Package] = []

        # 3.1 check branch mismatching
        self.logger.info(f"Checking ISO image '{self.image.image.name}' branch")
        branch, date = self._find_base_repo(self.image.image.packages)
        self.logger.info(
            f"Most likely branch for '{self.image.image.name}' is '{branch}' on '{date}'"
        )
        # 3.2 check all RPM packages in database
        self.logger.info(f"Checking ISO image '{self.image.image.name}' packages")
        missing = self._check_packages_in_db(self.image.image.packages)
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
            if not (self.config.dryrun or self.config.force):
                raise ImageProcessingPackageNotInDBError(missing=missing)
        # 4. build and store ISO image pkgset
        self._store_pkgsets(self._make_image_pkgsets())
