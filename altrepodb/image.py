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

import os
import lzma
import time
import shutil
import logging
import tarfile
import datetime
import tempfile
import libarchive
from collections import namedtuple
from dataclasses import asdict, dataclass
from typing import Union, Optional
from pathlib import Path
from uuid import uuid4

from .repo.packageset import PackageSetHandler
from .base import (
    Package,
    ImageMeta,
    PackageSet,
    ImageProcessorConfig,
    stringify_image_meta,
)
from .rpmdb import RPMDBPackages, RPMDBOpenError
from .logger import LoggerOptional
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
    # ImageProcessingBranchMismatchError,
    ImageProcessingPackageNotInDBError,
    ImageProcessingExecutableNotFoundError,
)
from .utils import (
    bytes2human,
    run_command,
    cvt_ts_to_datetime,
    checksums_from_file,
)
from .database import DatabaseClient


#  custom types
_StringOrPath = Union[str, Path]

# module constants
RUN_COMMAND_TIMEOUT = 30
TAR_RPMDB_PREFIX = "./var/lib/rpm/"
IMG_RPMDB_PREFIX = "var/lib/rpm"
QCOW_RPMDB_PREFIX = "var/lib/rpm"
LOCALTMP_PREFIX = "tmp_img"
REQUIRED_EXECUTABLES = (
    "unxz",
    "umount",
    "gost12sum",
    "guestmount",
)


@dataclass
class ImageMounter:
    name: str
    type: str
    path: str
    ismount: bool
    _log: logging.Logger
    _tmpdir: tempfile.TemporaryDirectory
    _image_path: str

    def __init__(
        self,
        image_name: str,
        image_path: str,
        image_type: str,
        logger: LoggerOptional = None,
    ):
        if logger is not None:
            self._log = logger
        else:
            self._log = logging.getLogger(__name__ + "." + self.__class__.__name__)

        self.name = image_name
        self.type = image_type

        if image_type not in ("img", "tar", "qcow"):
            self._log.error(f"Unsupported filesystem image type {image_type}")
            raise ImageTypeError(self.name, self.type)

        self._image_path = image_path
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path: str = self._tmpdir.name
        self.ismount: bool = False
        self._localtmpfile: Optional[Path] = None

    def __run_command(
        self, *args, env: Optional[dict[str, str]], check: bool, timeout: int
    ):
        try:
            cmdline_, stdout_, stderr_, retcode_ = run_command(
                *args,
                env=env,
                raise_on_error=check,
                logger=self._log,
                timeout=timeout,
            )
        except RunCommandError as e:
            raise ImageRunCommandError("Subprocess returned an error") from e

        return cmdline_, stdout_, stderr_, retcode_

    def _run_command(self, *args, env):
        _ = self.__run_command(
            *args,
            env=env,
            check=True,
            timeout=RUN_COMMAND_TIMEOUT,
        )

    def _unmount(self) -> None:
        self._log.info(f"Unmounting {self.path}...")
        try:
            if self.type in ("img", "qcow"):
                self._run_command("umount", self.path, env=None)
            else:
                pass
        except ImageRunCommandError as e:
            raise ImageUnmountError(self._image_path, self.path) from e

    def _mount_tar(self) -> None:
        try:
            self._log.info("Mounting TAR archive")
            with libarchive.file_reader(self._image_path) as arch:
                for entry in arch:
                    # copy '/etc/os-release' file to temporary directory
                    if entry.name.endswith("os-release"):
                        c = b""
                        for b in entry.get_blocks():
                            c += b
                        Path(self.path).joinpath("os-release").write_text(
                            c.decode("utf-8")
                        )
                    # extract RPMDB files to temporary directory
                    if entry.name.startswith(TAR_RPMDB_PREFIX):
                        if entry.isfile:
                            e_name = entry.name.replace(TAR_RPMDB_PREFIX, "")
                            c = b""
                            with Path(self.path).joinpath(e_name).open("wb") as f:
                                for b in entry.get_blocks():
                                    f.write(b)
                    # clean RPM DB cache files
                    # XXX: fix 'error: cannot open Packages index using db4 -  (-30971)'
                    for f in Path(self.path).glob("**/__db.*"):
                        f.unlink()
        except Exception as e:
            raise ImageMountError(self._image_path, self.path) from e

    def _mount_qcow(self) -> None:
        # supbrocess args
        args = (
            "guestmount",
            "-a",
            self._image_path,
            "-i",
            "--ro",
            self.path,
        )
        # pass environment variables to subprocess
        env = os.environ.copy()
        env["LIBGUESTFS_BACKEND"] = "direct"

        self._log.info(f"Mounting filesystem image {self._image_path} to {self.path}")
        try:
            self._run_command(*args, env=env)
        except ImageRunCommandError as e:
            raise ImageMountError(self._image_path, self.path) from e

    def _mount_img(self) -> None:
        image_path = self._image_path
        # check if image is compressed
        if image_path.endswith(".img.xz"):
            self._log.info(f"Uncompressing filesystem image {self.name}")
            # uncompress image to local temporary folder
            # 1. check if there is enogh space for uncompressed image
            # 1.1 get uncompressed archive size by pasing 'unxz -lv' output
            _, sout, _, _ = self.__run_command(
                *("unxz", "-lv", image_path),
                env=None,
                check=True,
                timeout=RUN_COMMAND_TIMEOUT,
            )
            u_size = 0
            for line in sout.splitlines():
                if line.strip().startswith("Uncompressed size:"):
                    u_size = int(line.replace("\u202f", "").split("(")[-1][:-3])
                    break
            self._log.info(f"Uncompressed image size is {bytes2human(u_size)}")
            if u_size == 0:
                raise ImageProcessingError("Failed to get uncompressed image size")
            # 1.2 check if there is enough space in user home directory
            homedir = Path.home()
            st_ = os.statvfs(homedir)
            freespace = st_.f_bsize * st_.f_bavail
            if (u_size * 1.1) > freespace:
                raise ImageProcessingError(
                    "Not enough space to umcompress filesystem image"
                )

            # 2. uncompress image
            # 2.1 setup temporary file name
            self._localtmpfile = homedir.joinpath(
                "_".join((LOCALTMP_PREFIX, str(uuid4())))
            )
            # 2.2 uncompress 'img.xz' to temporary file
            st = time.time()
            with lzma.open(image_path, "rb") as arch:
                with open(self._localtmpfile, "wb") as tmpfile:
                    for chunk in iter(lambda: arch.read(4096), b""):
                        tmpfile.write(chunk)
            self._log.info(
                f"Filesystem image decompressed in {(time.time() - st):.3f} seconds"
            )
        # mount filesystem image
        if self._localtmpfile is not None:
            image_path = str(self._localtmpfile)
        # supbrocess args
        args = (
            "guestmount",
            "-a",
            image_path,
            "-i",
            "--ro",
            self.path,
        )
        # pass environment variables to subprocess
        env = os.environ.copy()
        env["LIBGUESTFS_BACKEND"] = "direct"
        self._log.info(f"Mounting filesystem image {image_path} to {self.path}")
        try:
            self._run_command(*args, env=env)
        except ImageRunCommandError as e:
            raise ImageMountError(self._image_path, self.path) from e

    def _mount(self) -> None:
        if self.type == "img":
            self._mount_img()
        elif self.type == "tar":
            self._mount_tar()
        elif self.type == "qcow":
            self._mount_qcow()

    def open(self):
        if not self.ismount:
            try:
                self._mount()
                self.ismount = True
            except Exception as e:
                self._tmpdir.cleanup()
                if self._localtmpfile is not None:
                    self._localtmpfile.unlink(missing_ok=True)
                    self._localtmpfile = None
                raise e

    def close(self):
        if self.ismount:
            try:
                self._unmount()
            except Exception as e:
                raise e
            finally:
                self.ismount = False
            self._tmpdir.cleanup()
            if self._localtmpfile is not None:
                self._localtmpfile.unlink(missing_ok=True)
                self._localtmpfile = None


@dataclass
class FylesystemImageMeta:
    mtime: str = ""
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


class ImageHandler:
    """Image handler base class."""

    def __init__(self, name: str, path: _StringOrPath):
        self._parsed = False
        self.logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.name = name
        self.path = str(path)
        self._image: FilesystemImage = None  # type: ignore

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

    def _validate_image(self):
        raise NotImplementedError

    def _open_image(self):
        try:
            self.logger.info(f"Opening {self.name} filesystem image")
            self._image.mount.open()
        except Exception as e:
            self.logger.error(f"Failed to mount filesystem image {self.path}")
            raise ImageOpenError(self.path) from e

    def _get_checksums(self):
        self.logger.info("Calculate MD5, SHA1, SHA256 and GOST12 checksums from file")
        try:
            md5_, sha256_, gost12_ = checksums_from_file(self.path)
            self._image.meta.md5_cs = md5_
            self._image.meta.sha256_cs = sha256_
            self._image.meta.gost12_cs = gost12_
        except Exception as e:
            self.logger.error("Failed to calculate image checksums")
            raise ImageProcessingError from e

    def _process_image(self):
        raise NotImplementedError

    def run(self):
        self.logger.info(f"Processing {self.name} filesystem image")
        try:
            self._check_system_executables()
            self._validate_image()
            self._open_image()
            self._get_checksums()
            self._process_image()
            self._parsed = True
        except ImageProcessingError as e:
            self.logger.error(
                "Error occured while processing filesystem image", exc_info=True
            )
            raise e
        finally:
            self._close()

    @property
    def image(self) -> FilesystemImage:
        if not self._parsed:
            self.run()
        return self._image


class TAR(ImageHandler):
    def __init__(
        self, name: str, path: _StringOrPath, logger: LoggerOptional = None
    ) -> None:
        super().__init__(name, path)

        if logger is not None:
            self.logger = logger

        p = Path(self.path)
        self._image = FilesystemImage(
            name=self.name,
            path=self.path,
            size=p.stat().st_size,
            type="tar",
            meta=FylesystemImageMeta(
                mtime=cvt_ts_to_datetime(int(p.stat().st_mtime)).isoformat()
            ),
            mount=ImageMounter(self.name, self.path, "tar", self.logger),
            packages=list(),
        )

        self._parsed = False

    def _validate_image(self):
        if not tarfile.is_tarfile(self.path):
            self.logger.error(f"{self.path} not a valid TAR file")
            raise ImageInvalidError(self.path)

    def _process_image(self):
        p = Path(self._image.mount.path)

        # get '/etc/os-release' contents
        if p.joinpath("os-release").exists():
            self._image.meta.osrelease = p.joinpath("os-release").read_text()

        # read packages from RPMDB
        self.logger.debug("Reading filesystem image RPM packages")
        try:
            rpmdb = RPMDBPackages(p)
            self._image.packages = rpmdb.packages_list
            self.logger.info(
                f"Collected {rpmdb.count} RPM packages from '{self.name}' filesystem image"
            )
        except RPMDBOpenError:
            self.logger.error(
                f"No RPM packages found in '{self.name}' filesystem image"
            )
            raise ImageProcessingError("No packages found")


class QCOW(ImageHandler):
    def __init__(
        self, name: str, path: _StringOrPath, logger: LoggerOptional = None
    ) -> None:
        super().__init__(name, path)

        if logger is not None:
            self.logger = logger

        p = Path(self.path)
        self._image = FilesystemImage(
            name=self.name,
            path=self.path,
            size=p.stat().st_size,
            type="qcow",
            meta=FylesystemImageMeta(
                mtime=cvt_ts_to_datetime(int(p.stat().st_mtime)).isoformat()
            ),
            mount=ImageMounter(self.name, self.path, "qcow", self.logger),
            packages=list(),
        )

        self._parsed = False

    def _validate_image(self):
        if not (self.path.endswith(".qcow2") or self.path.endswith(".qcow2c")):
            self.logger.error(f"{self.path} not a valid QCOW2 file")
            raise ImageInvalidError(self.path)

    def _process_image(self):
        p = Path(self._image.mount.path)

        # get '/etc/os-release' contents
        if p.joinpath("/etc/os-release").exists():
            self._image.meta.osrelease = p.joinpath("/etc/os-release").read_text()

        # read packages from RPMDB
        self.logger.debug("Reading filesystem image RPM packages")
        try:
            rpmdb = RPMDBPackages(p.joinpath(QCOW_RPMDB_PREFIX))
            self._image.packages = rpmdb.packages_list
            self.logger.info(
                f"Collected {rpmdb.count} RPM packages from '{self.name}' filesystem image"
            )
        except RPMDBOpenError:
            self.logger.error(
                f"No RPM packages found in '{self.name}' filesystem image"
            )
            raise ImageProcessingError("No packages found")


class IMG(ImageHandler):
    def __init__(
        self, name: str, path: _StringOrPath, logger: LoggerOptional = None
    ) -> None:
        super().__init__(name, path)

        if logger is not None:
            self.logger = logger

        p = Path(self.path)
        self._image = FilesystemImage(
            name=self.name,
            path=self.path,
            size=p.stat().st_size,
            type="img",
            meta=FylesystemImageMeta(
                mtime=cvt_ts_to_datetime(int(p.stat().st_mtime)).isoformat()
            ),
            mount=ImageMounter(self.name, self.path, "img", self.logger),
            packages=list(),
        )

        self._parsed = False

    def _validate_image(self):
        if not (self.path.endswith(".img") or self.path.endswith(".img.xz")):
            self.logger.error(f"{self.path} not a valid filesystem image file")
            raise ImageInvalidError(self.path)

    def _process_image(self):
        p = Path(self._image.mount.path)

        # get '/etc/os-release' contents
        if p.joinpath("/etc/os-release").exists():
            self._image.meta.osrelease = p.joinpath("/etc/os-release").read_text()

        # read packages from RPMDB
        self.logger.debug("Reading filesystem image RPM packages")
        try:
            rpmdb = RPMDBPackages(p.joinpath(IMG_RPMDB_PREFIX))
            self._image.packages = rpmdb.packages_list
            self.logger.info(
                f"Collected {rpmdb.count} RPM packages from '{self.name}' filesystem image"
            )
        except RPMDBOpenError:
            self.logger.error(
                f"No RPM packages found in '{self.name}' filesystem image"
            )
            raise ImageProcessingError("No packages found")


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

    get_last_image_status = """
SELECT
    img_branch,
    img_edition,
    argMax(img_show, ts)
FROM ImageStatus
WHERE img_branch = '{branch}' AND img_edition = '{edition}'
GROUP BY img_branch, img_edition
"""

    get_last_img_tag_status = """
SELECT
    img_tag,
    argMax(img_show, ts)
FROM ImageTagStatus
WHERE img_tag = '{img_tag}'
GROUP BY img_tag
"""

    insert_image_status = """
INSERT INTO ImageStatus (*) VALUES
"""

    insert_image_tag_status = """
INSERT INTO ImageTagStatus (*) VALUES
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
            self.logger = logging.getLogger(__name__)

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
            self.image = IMG(
                name=self.meta.file, path=self.config.path, logger=self.logger
            )
        elif self.meta.image_type == "qcow":
            self.image = QCOW(
                name=self.meta.file, path=self.config.path, logger=self.logger
            )
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

    def _find_base_repo(self, packages: list[Package]):
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
            if not (self.config.dryrun or self.config.force):
                raise ImageProcessingGuessBranchError
            self.logger.warning(f"Failed to guess base branch for {self.meta.file}")
        else:
            branch, date = res[0]
            self.logger.info(
                f"Most likely branch for '{self.image.image.name}' is '{branch}' on '{date}'"
            )
        # 5. cleaun-up
        res = self.conn.execute(self.sql.drop_tmp_table.format(tmp_table=tmp_table))

    def _check_packages_in_db(self, packages: list[Package]):
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
                if p.hash in not_found_:
                    not_found.append(p)
        # 4. cleaun-up
        res = self.conn.execute(self.sql.drop_tmp_table.format(tmp_table=tmp_table))

        # return not_found
        if not_found:
            msg = (
                f"{len(not_found)} packages not found in database\n"
                + "\n".join(
                    [
                        f"[{p.hash}] {p.name}-{p.version}-{p.release} {p.arch}"
                        for p in not_found
                    ]
                )
            )
            self.logger.debug(
                f"Packages not found in database:\n{[p for p in not_found]}"
            )
            if not (self.config.dryrun or self.config.force):
                self.logger.error(msg)
                raise ImageProcessingPackageNotInDBError(missing=not_found)
            self.logger.warning(msg)

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
        # store image pkgset
        psh = PackageSetHandler(conn=self.conn)
        # load image package set components from leaves to root
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

    def _update_image_status(self):
        ImageStatus = namedtuple(
            "ImageStatus",
            [
                "img_branch",
                "img_edition",
                "img_name",
                "img_show",
                "img_start_date",
                "img_end_date",
                "img_summary_ru",
                "img_summary_en",
                "img_description_ru",
                "img_description_en",
                "img_mailing_list",
                "img_name_bugzilla",
                "img_json",
            ],
            defaults=[
                "",    # img_summary_ru
                "",    # img_summary_en
                "",    # img_description_ru
                "",    # img_description_ru
                "",    # img_mailing_list
                "",    # img_name_bugzilla
                "{}",  # img_hson
            ],
        )
        # get last repositroy status from DB
        res = self.conn.execute(
            self.sql.get_last_image_status.format(
                branch=self.meta.branch, edition=self.meta.edition
            )
        )
        if not res:
            # if no record found in DB then create new one
            ims = ImageStatus(
                img_branch=self.meta.branch,
                img_edition=self.meta.edition,
                img_name=(
                    f"{self.meta.edition.upper()} "
                    f"{self.meta.version_major}.{self.meta.version_minor} "
                    f"{self.meta.arch}"
                ),  # oficial image name placeholder
                img_show=0,
                img_start_date=datetime.datetime.now(),
                img_end_date=datetime.datetime(2099, 1, 1),
                img_json="{}",  # JSON string placeholder
                img_summary_ru=f"{self.meta.branch} {self.meta.edition}",
                img_summary_en=f"{self.meta.branch} {self.meta.edition}",
            )
            # store new ImageStatus record to DB
            if not self.config.dryrun:
                res = self.conn.execute(
                    self.sql.insert_image_status,
                    [
                        ims._asdict(),
                    ],
                )
        # get last image tag status from DB
        res = self.conn.execute(
            self.sql.get_last_img_tag_status.format(img_tag=self.tag)
        )
        if not res:
            # store new ImageTagStatus record
            if not self.config.dryrun:
                res = self.conn.execute(
                    self.sql.insert_image_tag_status,
                    [
                        {"img_tag": self.tag, "img_show": 0},
                    ],
                )

    def run(self) -> None:
        st = time.time()
        # 1. check if image is already loaded to DB
        if not self.config.force:
            if self._check_image_tag_date_in_db(self.tag, self.meta.date):
                self.logger.info(f"Filesystem image '{self.tag}' already exists in database")
                if not self.config.dryrun:
                    return
        # 2. mount and parse filesystem image
        self.image.run()
        self.logger.info(f"Image tag : {self.tag}")
        self.logger.info(f"Image 'os-release' :\n{self.image.image.meta.osrelease}")
        # 3. check filesystem packages in branch
        # missing: list[Package] = []
        pass
        # 3.1 check branch mismatching
        self.logger.info(f"Checking filesystem image '{self.image.image.name}' branch")
        self._find_base_repo(self.image.image.packages)
        # 3.2 check all RPM packages in database
        self.logger.info(f"Checking filesystem image '{self.image.image.name}' packages")
        self._check_packages_in_db(self.image.image.packages)
        # 4. build and store filesystem image pkgset
        self._store_pkgsets(self._make_image_pkgsets())
        # 5. update repository status record with loaded imgae
        self._update_image_status()
        # 6. clean-up
        self.conn.disconnect()
        # 7. log summary
        self.logger.info(f"Image processed in {(time.time() - st):.3f} seconds")
