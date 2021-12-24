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

from datetime import datetime
import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import Union
from pathlib import Path

from .base import File, Package, ISOProcessorConfig, DEFAULT_LOGGER, PkgHash
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
            _, _, _, _ = run_command(*args, raise_on_error=True, logger=self._log)
        except RunCommandError as e:
            raise ImageMounterRunCommandError(
                "Subprocess commandline returned non zero code"
            ) from e

    def _unmount(self, path: str) -> None:
        self._log.info(f"unmounting {path}...")
        try:
            self._run_command("umount", path)
        except ImageMounterRunCommandError as e:
            raise ImageMounterUnmountError(self._image_path, self.path) from e

    def _mount_iso(self, iso_path: str, mount_path: str) -> None:
        self._log.info(f"mounting ISO image {iso_path} to {mount_path}")
        try:
            self._run_command("fuseiso", iso_path, mount_path)
        except ImageMounterRunCommandError as e:
            raise ImageMounterMountError(self._image_path, self.path) from e

    def _mount_sqfs(self, iso_path: str, mount_path: str) -> None:
        self._log.info(f"mounting SquashFS image {iso_path} to {mount_path}")
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
                    f"failed to mount {self.type} image {self._image_path} to {self.path}"
                )
                self._tmpdir.cleanup()
                raise e

    def close(self):
        if self.ismount:
            try:
                self._unmount(self.path)
            except Exception as e:
                self._log.error(f"failed to mount {self.type} image at {self.path}")
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
    isoinfo: list[str]


@dataclass
class ISOImage:
    name: str
    path: str
    meta: ISOImageMeta
    mount: ImageMounter
    packages: list[Package]


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
                isoinfo=[],
            ),
            mount=ImageMounter("ISO", self.iso_path, "iso", self.logger),
            packages=[],
        )

    def __del__(self):
        self._close()

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

        if os.path.isdir(self._iso.path):
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
                self.logger.error(
                    f"Failed to calculate MD5 checksum from file {file.name}"
                )
        file_ = File(
            md5=md5_,  # type: ignore
            name=str(Path(file).relative_to(Path.cwd())),
            size=stat_.st_size,
            linkto=link_,
            # flag=0,  # FIXME: st_flags not supported
            # lang="",  # FIXME: get whatever suitable here
            mode=stat_.st_mode,
            rdev=stat_.st_rdev,
            mtime=int(stat_.st_mtime),
            class_=class_,
            device=stat_.st_dev,
            username=uid_lut.get(stat_.st_uid, ""),
            groupname=gid_lut.get(stat_.st_gid, ""),
            # verifyflag=0,  # FIXME: get xattrs as UInt32 value somehow
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
            self._iso.meta.isoinfo = out.split("\n")
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
                self.logger.info(f"Collecting SquashFs image files information")
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
    AND pkg_hash IN (
        SELECT * FROM {tmp_table}
    )
GROUP BY pkgset_name
ORDER BY cnt DESC
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
SELECT * FROM {tpm_table1}
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


class ISOProcessor:
    def __init__(self, config: ISOProcessorConfig) -> None:
        self.config = config
        self.sql = SQL()

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
            iso_name=self.config.name, iso_path=self.config.path, logger=self.logger
        )

    def _find_base_repo(self, packages: list[Package]) -> str:
        # find base branch by packages list with last_packages
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
        # 3. get most likely base branch
        res = self.conn.execute(
            self.sql.get_branch_by_packages.format(tmp_table=tmp_table)
        )
        branch = res[0][0]
        # 4. cleaun-up
        res = self.conn.execute(self.sql.drop_tmp_table.format(tmp_table=tmp_table))
        return branch

    def _check_packages_in_db(self, packages: list[Package]) -> tuple[bool, list[Package]]:
        # check if packages is in database
        all_ok: bool = False
        not_found: list[Package] = []

        return all_ok, not_found

    def _find_packages_from_files(self, sqfs: SquashFSImage, branch: str = "") -> tuple[list[Package], list[File]]:
        # find packages by files using branch constraint and orphaned files
        packages: list[Package] = []
        orphan_files: list[File] = []

        if branch == "":
            branch = self.config.branch

        # 1. create temporary table
        tmp_table = "_tmpFiles"
        res = self.conn.execute(
            self.sql.create_tmp_table.format(
                tmp_table=tmp_table, columns="(file_hashname UInt64, file_md5 FixedString(16))"
            )
        )
        # 2. insert package hashes
        res = self.conn.execute(
            self.sql.insert_into_tmp_table.format(tmp_table=tmp_table),
            ({"file_hashname": mmhash(f.name), "file_md5": f.md5} for f in sqfs.files),
            settings={"strings_as_bytes": True}
        )
        # 3. get packages by files
        pass

        return packages, orphan_files

    def _process_squashfs_files(self, sqfs: SquashFSImage, branch: str = "") -> tuple[Package, list[File]]:
        """Builds metapackage with orphaned files and updates SquashFS object packages and files."""

        # 1. get packages and orphaned files for SquashFS image
        packages, orphan_files = self._find_packages_from_files(sqfs=sqfs, branch=branch)
        self.logger.info(f"Found {len(packages)} packages for '{sqfs.name}' SquashFS image")
        self.logger.info(f"Found {len(orphan_files)} orphaned files in '{sqfs.name}' SquashFS image")
        # 2. make metapackage
        iso_name_ = self.config.name.replace(" ", "_")
        iso_date_ = self.config.date.strftime("%Y%m%d")
        iso_date_ = self.iso.iso.meta.date or iso_date_
        orphan_package = Package(
            hash=sqfs.meta.hash,
            name=f"{sqfs.name}-orphaned-files-{iso_name_}-{iso_date_}",
            arch=self.iso.iso.meta.arch,
            buildtime=sqfs.meta.mtime,
            is_srpm=False
        )
        self.logger.info(f"Built '{orphan_package.name}' metapackage for orphaned files in '{sqfs.name}' image")
        # 3. update SquashFS object
        sqfs.files = orphan_files
        sqfs.packages = packages
        sqfs.packages.append(orphan_package)

        return orphan_package, orphan_files

    def _store_orphaned(self, sqfs: SquashFSImage, package: Package, files: list[File]) -> None:
        # store SquashFS metapackage for orphaned files
        # files for metapackage are stored too
        # 1. make package hashes
        pkg_hash = PkgHash(
            sf=sqfs.meta.hash,
            md5=b"",
            sha1=sqfs.meta.sha1,
            sha256=b"",
            blake2b=b""
        )
        # 2. store files
        pass
        # 3. store package
        pass

    def _make_iso_pkgset(self) -> None:
        # build packageset structure from ISO image for PackageSetName table
        # depth 0: root: ISO itself with meta information in 'pkgset_kv' fields
        # depth 1: 'rpms': RPM packages found at ISO itself if any
        # depth 1: '%sqfs.name': for SquashFS images that contains RPM packages
        # depth 1: '%sqfs.name': for SquashFS images that doesn't contains RPM packages
        pass

    def _store_iso_pkgset(self) -> None:
        # store ISO image pkgset
        pass

    def run(self) -> None:
        self.iso.run()
        # 1. check ISO packages in branch
        all_ok: bool = False
        missing: list[Package] = []

        if self.iso.iso.packages:
            # 1.1 check branch mismatching
            self.logger.info(f"Checking ISO image {self.iso.iso.name} branch")
            branch = self._find_base_repo(self.iso.iso.packages)
            if branch != self.config.branch:
                self.logger.warning(
                    f"Branch '{self.config.branch}' from config not match "
                    f"with branch '{branch}' from ISO image packages"
                )
                # if not self.config.dryrun:
                #     raise ISOProcessingBranchMismatchError(
                #         cfg_branch=self.config.branch, pkg_branch=branch
                #     )
            #  1.2 check all RPM packages in database
            self.logger.info(f"Checking ISO image packages")
            all_ok, missing = self._check_packages_in_db(self.iso.iso.packages)
            if not all_ok:
                self.logger.error(
                    f"{len(missing)} packages not found in database\n"
                    + "\n".join([p.name for p in missing])
                )
                if not self.config.dryrun:
                    raise ISOProcessingPackageNotInDBError(missing=missing)
        # 2. check SquashFS packages consistency
        for sqfs in self.iso.sqfs:
            if not sqfs.packages:
                continue
            # 2.1 check branch mismatching
            self.logger.info(f"Checking SquashFS image {sqfs.name} branch")
            branch = self._find_base_repo(sqfs.packages)
            if branch != self.config.branch:
                self.logger.warning(
                    f"Branch '{self.config.branch}' from config not match with "
                    f"branch '{branch}' from '{sqfs.name}' SquashFS image packages"
                )
                # if not self.config.dryrun:
                #     raise ISOProcessingBranchMismatchError(
                #         cfg_branch=self.config.branch, pkg_branch=branch
                #     )
            #  2.2 check all RPM packages in database
            all_ok = False
            missing = []
            self.logger.info(f"Checking SquashFS image {sqfs.name} packages")
            all_ok, missing = self._check_packages_in_db(sqfs.packages)
            if not all_ok:
                self.logger.error(
                    f"{len(missing)} packages not found in database\n"
                    + "\n".join([p.name for p in missing])
                )
                if not self.config.dryrun:
                    raise ISOProcessingPackageNotInDBError(missing=missing)
        # 3. Proceed with SquashFS images without packages
        for sqfs in self.iso.sqfs:
            if sqfs.packages or not sqfs.files:
                continue
            self.logger.info(f"Processing SquashFS image {sqfs.name} files")
            o_package, o_files = self._process_squashfs_files(sqfs)
            if not self.config.dryrun:
                self._store_orphaned(sqfs, o_package, o_files)
        # 4. build ISO image pkgset
        self._make_iso_pkgset()
        # 5. store ISO image pkgset
        self._store_iso_pkgset()
