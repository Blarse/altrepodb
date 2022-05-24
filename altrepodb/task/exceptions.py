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


class TaskLoaderError(Exception):
    pass


class TaskLoaderInvalidPathError(TaskLoaderError):
    def __init__(self, path: str):
        self.path = path
        super().__init__(f"Invalid task path {self.path}")


class TaskLoaderProcessingError(TaskLoaderError):
    def __init__(self, id: int, exc: Exception):
        self.id = id
        self.exc = exc
        super().__init__(
            f"An error occured while loadint task {id} to database. Error: {exc}"
        )


class TaskLoaderParserError(TaskLoaderError):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)
