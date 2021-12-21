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
import shutil
import tempfile
from dataclasses import dataclass
from typing import Union
from pathlib import Path

from altrepodb.base import File, Package, DEFAULT_LOGGER
from altrepodb.rpmdb import RPMDBPackages, RPMDBOpenError
from altrepodb.logger import ConsoleLogger, FakeLogger, LoggerProtocol, _LoggerOptional
from altrepodb.exceptions import (
    RunCommandError,
    ImageMounterMountError,
    ImageMounterUnmountError,
    ImageMounterImageTypeError,
    ImageMounterRunCommandError,
    ISOImageOpenError,
    ISOProcessingError,
    ISOImageInvalidError,
    ISOProcessingExecutableNotFoundError,
)
from altrepodb.utils import (
    run_command,
    snowflake_id_sqfs,
    md5_from_file,
    sha1_from_file,
)


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
            self._log = logger
        else:
            self._log = DEFAULT_LOGGER(name="ISO")
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
            mount=ImageMounter("ISO", self.iso_path, "iso", self._log),
            packages=[],
        )

    def __del__(self):
        self._close()

    def _close(self) -> None:
        self._log.info(f"Closing {self._iso.name} ISO image")
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
                self._log.error(f"Executable '{executable}' not found")
                not_found_.append(executable)
        if not_found_:
            not_found_ = ", ".join(not_found_)
            raise ISOProcessingExecutableNotFoundError(not_found_)

    def _open_iso(self) -> None:
        """Open ISO image for file processing."""

        if os.path.isdir(self._iso.path):
            self._log.error(f"{self._iso.path} is not an ISO image")
            raise ISOImageInvalidError(self._iso.path)

        try:
            self._log.info(f"Opening {self._iso.name} ISO image")
            self._iso.mount.open()
        except Exception as e:
            self._log.error(f"Failed to mount ISO image {self._iso.path}")
            raise ISOImageOpenError(self._iso.path) from e

        self._log.info(f"Processing SquashFS images from ISO")
        for sqfs_name in ("live", "rescue", "altinst"):
            sqfs_path = os.path.join(self._iso.mount.path, sqfs_name)
            if os.path.isfile(sqfs_path):
                self._log.info(
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
                    mount=ImageMounter(sqfs_name, sqfs_path, "squashfs", self._log),
                )
                try:
                    self._log.info(f"Opening '{sqfs_name}' SquashFS image")
                    sqfs.mount.open()
                    self._sqfs.append(sqfs)
                except Exception as e:
                    self._log.error(f"Failed to mount '{sqfs_name}' SquashFS image")
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
                self._log.error(
                    f"failed to calculate MD5 checksum from file {file.name}"
                )
        file_ = File(
            md5=md5_,  # type: ignore
            name=str(Path(file).relative_to(Path.cwd())),
            size=stat_.st_size,
            linkto=link_,
            flag=0,  # FIXME: st_flags not supported
            lang="",  # FIXME: get whatever suitable here
            mode=stat_.st_mode,
            rdev=stat_.st_rdev,
            mtime=int(stat_.st_mtime),
            class_=class_,
            device=stat_.st_dev,
            username=uid_lut.get(stat_.st_uid, ""),
            groupname=gid_lut.get(stat_.st_gid, ""),
            verifyflag=0,  # FIXME: get xattrs as UInt32 value somehow
        )
        return file_

    def _process_iso(self):
        # read ISO image meta information
        self._log.info(f"Gathering ISO image meta information")
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
            logger=self._log,
        )
        if errcode == 0:
            self._iso.meta.isoinfo = out.split("\n")
        self._log.debug(f"ISO image meta information: {self._iso.meta}")
        # parse ISO image packages
        self._log.info(f"Gathering ISO image RPM packages information")
        iso_rpms_dir = Path(self._iso.mount.path).joinpath("ALTLinux")
        if iso_rpms_dir.is_dir():
            for pkg in (
                p
                for p in iso_rpms_dir.joinpath("RPMS.main").iterdir()
                if p.is_file() and p.name.endswith(".rpm")
            ):
                self._iso.packages.append(RPMDBPackages.get_package_info(pkg))
        self._log.info(
            f"Collected {len(self._iso.packages)} RPM packages from {self.iso_path}/ALTLinux/RPMS.main"
        )

    def _process_squashfs(self):
        self._log.info(f"Gathering SquashFS images meta information")
        # save CWD
        cwd_ = Path.cwd()
        for sqfs in self._sqfs:
            self._log.info(f"Processing '{sqfs.name}' SquashFS image")
            # get SquashFS meta information
            self._log.debug(f"Calculate SquashFs image SHA1 checksum")
            sqfs.meta.sha1 = sha1_from_file(Path(self._iso.mount.path).joinpath(sqfs.name), as_bytes=True)  # type: ignore
            sqfs.meta.hash = snowflake_id_sqfs(mtime=sqfs.meta.mtime, sha1=sqfs.meta.sha1, size=sqfs.meta.size)  # type: ignore
            # parse SquashFS images packages and files
            self._log.debug(f"Reading SquashFs image RPM packages")
            try:
                rpmdb = RPMDBPackages(
                    str(Path(sqfs.mount.path).joinpath("var/lib/rpm"))
                )
                sqfs.packages = rpmdb.packages_list
                self._log.info(
                    f"Collected {rpmdb.count} RPM packages from '{sqfs.name}' SquashFS image"
                )
            except RPMDBOpenError:
                self._log.info(f"No RPM packages found in '{sqfs.name}' SquashFS image")
            if not sqfs.packages:
                self._log.info(f"Collecting SquashFs image files information")
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
                self._log.info(
                    f"Collected {len(sqfs.files)} files from '{sqfs.name}' SquashFS image"
                )
        # restore work directory
        os.chdir(cwd_)

    def _run(self):
        self._log.info(f"Processing {self._iso.name} ISO image")
        self._check_system_executables()
        try:
            self._open_iso()
            self._process_iso()
            self._process_squashfs()
            self._parsed = True
        except ISOProcessingError:
            # do something if needed
            raise
        finally:
            self._close()

    @property
    def iso(self) -> ISOImage:
        if not self._parsed:
            self._run()
        return self._iso

    @property
    def sqfs(self) -> list[SquashFSImage]:
        if not self._parsed:
            self._run()
        return self._sqfs
