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


class PackageLoadError(Exception):
    """Raised from PackageLoader worker."""

    def __init__(self, message: str):
        self.message = message
        super().__init__()


class RepoParsingError(Exception):
    """Raised when error occured during repository structure parsing."""

    pass


class RepoProcessingError(Exception):
    """Raised when error occured during repository processing."""

    pass
