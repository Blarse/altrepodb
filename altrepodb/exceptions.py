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

from typing import Any


class RunCommandError(Exception):
    """Raises when subprocess command returned non zero code."""

    def __init__(self, message: str):
        self.message = message


# Threaded workers exception
class RaisingThreadError(Exception):
    """Custom exception class used in RaisingThread subclasses

    Args:
        message (string): exception message
        traceback (string): traceback of exception that raised in thread
    """

    def __init__(self, message: str, traceback: Any = None) -> None:
        self.message = message
        self.traceback = traceback
        super().__init__()


# ISO processing exceptions
class ImageProcessingError(Exception):
    pass


class ImageProcessingExecutableNotFoundError(ImageProcessingError):
    """Rises when required executables not found in system."""

    def __init__(self, executable: str):
        self.executable = executable
        super().__init__(f"Executables [{self.executable}] not found in system path")


class ImageProcessingBranchMismatchError(ImageProcessingError):
    """Rises when provided branch mismatch with branch from RPM packages."""

    def __init__(self, cfg_branch: str, pkg_branch: str):
        self.cfg_branch = cfg_branch
        self.pkg_branch = pkg_branch
        super().__init__(
            f"Branch '{self.cfg_branch}' from config not match with "
            f"branch '{self.pkg_branch}' from ISO image packages"
        )


class ImageProcessingPackageNotInDBError(ImageProcessingError):
    """Rises when RPM package not found in database."""

    def __init__(self, missing: list):
        self.missing = missing
        super().__init__(f"{len(self.missing)} packages not found in database")


class ImageProcessingGuessBranchError(ImageProcessingError):
    """Rises when failed to guess branch by set of packages."""

    def __init__(self):
        super().__init__("Failed to guess branch by packages.")


class ImageInvalidError(ImageProcessingError):
    """Rises when provided path is not a valid image."""

    def __init__(self, path: str = ""):
        self.path = path
        super().__init__(f"{self.path} is not a valid image")


class ImageOpenError(ImageProcessingError):
    """Rises when provided path is not a valid image."""

    def __init__(self, path: str = ""):
        self.path = path
        super().__init__(f"Failed to open image {self.path}")


class ImageMountError(ImageProcessingError):
    """Rises when failed to mount image."""

    def __init__(self, image_path: str = "", mount_point: str = ""):
        self.image_path = image_path
        self.mount_point = mount_point
        super().__init__(
            f"Failed to mount image {self.image_path} in {self.mount_point}"
        )


class ImageUnmountError(ImageProcessingError):
    """Rises when failed to unmount image."""

    def __init__(self, image_path: str = "", mount_point: str = ""):
        self.image_path = image_path
        self.mount_point = mount_point
        super().__init__(
            f"Failed to unmount image {self.image_path} from {self.mount_point}"
        )


class ImageTypeError(ImageProcessingError):
    """Rises when found unsupported image type."""

    def __init__(self, image_name: str = "", image_type: str = ""):
        self.image_name = image_name
        self.image_type = image_type
        super().__init__(
            f"Image {self.image_name} has unsupported type {self.image_type}"
        )


class ImageRunCommandError(ImageProcessingError):
    """Rises when subprocess commandline exited with non zero code."""

    pass
