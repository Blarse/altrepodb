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


class ServiceError(Exception):
    pass


class ServiceUnexpectedMessage(ServiceError):
    def __init__(self, got: str, expected: str):
        super().__init__(f"Unexpected message '{got}', expected '{expected}'")


class ServiceFailMessage(ServiceError):
    def __init__(self):
        super().__init__("Service Failed")


class ServiceLoadConfigError(ServiceError):
    def __init__(self, message: str = ""):
        super().__init__(f"Service Load Config Error: {message}")


class ServiceStartError(ServiceError):
    pass
