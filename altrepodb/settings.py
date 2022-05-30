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

PROJECT_NAME = "altrepodb"

# logging related settings
DEFAULT_LOG_LEVEL = 20  # 10: DEBUG, 20: INFO, 30: WARNING, 40: ERROR, 50: CRITICAL
DEFAULT_LOG_FILE = f"/var/log/{PROJECT_NAME}/altrepodb.log"
MAX_LOG_FILE_SIZE = 2**24
MAX_LOG_FILE_PARTS = 10
