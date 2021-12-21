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

class RunCommandError(Exception):
    """Raises when subprocess command returned non zero code."""

    def __init__(self, message: str):
        self.message = message


class PackageLoadError(Exception):
    """Raised from PackageLoader worker."""

    def __init__(self, message=None):
        self.message = message
        super().__init__()


class NotImplementedError(Exception):
    """Exception raised for not implemented functional

    Attributes:
        function - not implemented function description
    """

    def __init__(self, message="Function not implemented", function=None):
        self.message = message
        self.function = function
        super().__init__()

# Threaded workers exception
class RaisingThreadError(Exception):
    """Custom exception class used in RaisingThread subclasses

    Args:
        message (string): exception message
        traceback (string): traceback of exception that raised in thread
    """

    def __init__(self, message=None, traceback=None) -> None:
        self.message = message
        self.traceback = traceback
        super().__init__()

# ISO processing exceptions
class ISOProcessingError(Exception):
    pass


class ISOProcessingExecutableNotFoundError(ISOProcessingError):
    """Rises when required executables not found in system."""

    def __init__(self, executable: str):
        self.executable = executable
        super().__init__(f"Executables [{self.executable}] not found in system path")


class ISOImageInvalidError(ISOProcessingError):
    """Rises when provided path is not an valid ISO image."""

    def __init__(self, path: str = ""):
        self.path = path
        super().__init__(f"{self.path} is not valid ISO image")


class ISOImageOpenError(ISOProcessingError):
    """Rises when provided path is not an valid ISO image."""

    def __init__(self, path: str = ""):
        self.path = path
        super().__init__(f"Failed to mount ISO image {self.path}")


class ImageMounterMountError(ISOProcessingError):
    """Rises when failed to mount image."""

    def __init__(self, image_path: str = "", mount_point: str = ""):
        self.image_path = image_path
        self.mount_point = mount_point
        super().__init__(
            f"Failed to mount image {self.image_path} in {self.mount_point}"
        )


class ImageMounterUnmountError(ISOProcessingError):
    """Rises when failed to unmount image."""

    def __init__(self, image_path: str = "", mount_point: str = ""):
        self.image_path = image_path
        self.mount_point = mount_point
        super().__init__(
            f"Failed to unmount image {self.image_path} from {self.mount_point}"
        )


class ImageMounterImageTypeError(ISOProcessingError):
    """Rises when found unsupported image type."""

    def __init__(self, image_name: str = "", image_type: str = ""):
        self.image_name = image_name
        self.image_type = image_type
        super().__init__(
            f"Image {self.image_name} has unsupported type {self.image_type}"
        )


class ImageMounterRunCommandError(ISOProcessingError):
    """Rises when subprocess commandline exited with non zero code."""

    pass