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

import threading
from typing import Generator


# Exceptions
class PackageLoadError(Exception):
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


#  Classes
class RaisingTread(threading.Thread):
    """Base threading class that raises exception stored in self.exc at join()"""

    def __init__(self, *args, **kwargs):
        self.exc = None
        self.exc_message = None
        self.exc_traceback = None
        super().__init__(*args, **kwargs)

    def join(self):
        super().join()
        if self.exc:
            raise RaisingThreadError(
                message=self.exc_message, traceback=self.exc_traceback
            ) from self.exc  # type: ignore


class LockedIterator:
    """Thread safe iterator wraper."""

    def __init__(self, it):
        self.it = it
        self.lock = threading.Lock()

    def __iter__(self):
        return self

    def __next__(self):
        with self.lock:
            return next(self.it)


class GeneratorWrapper:
    """Wraps generator function and allow to test it's emptyness at any time."""

    def __init__(self, iter: Generator):
        self.source = iter
        self.stored = False

    def __iter__(self):
        return self

    def __bool__(self):
        if self.stored:
            return True
        try:
            self.value = next(self.source)
            self.stored = True
        except StopIteration:
            return False
        return True

    def __next__(self):
        if self.stored:
            self.stored = False
            return self.value
        return next(self.source)
