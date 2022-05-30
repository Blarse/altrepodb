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

# altrepodb.repo
MAX_WORKERS_FOR_SRPM = 4
ARCHS = (
    "src",
    "aarch64",
    "armh",
    "i586",
    "ppc64le",
    "x86_64",
    "x86_64-i586",
    "noarch",
    "mipsel",
    "riscv64",
    "e2k",
    "e2kv4",
    "e2kv5",
    "e2kv6",
)

# altrepodb.uploaderd.uploaderd
DEFAULT_UPLOADERD_CONFIG_FILE = "/etc/uploaderd/config.json"
DEFAULT_SERVICE_CONF_DIR = "/etc/uploaderd/services.d/"
DEFAULT_BASE_TIMEOUT = 10

#  altrepodb.beehive
BEEHIVE_BASE_URL = "https://git.altlinux.org/beehive"
BEEHIVE_BRANCHES = (
    "Sisyphus",
    "p10",
    "p9",
)
BEEHIVE_ARCHS = ("i586", "x86_64")

# altrepodb.image
IMG_RUN_COMMAND_TIMEOUT = 30
IMG_TAR_RPMDB_PREFIX = "./var/lib/rpm/"
IMG_IMG_RPMDB_PREFIX = "var/lib/rpm"
IMG_QCOW_RPMDB_PREFIX = "var/lib/rpm"
IMG_LOCALTMP_PREFIX = "tmp_img"
IMG_REQUIRED_EXECUTABLES = (
    "unxz",
    "umount",
    "gost12sum",
    "guestmount",
)

# altrepodb.iso
ISO_RUN_COMMAND_TIMEOUT = 10
ISO_REQUIRED_EXECUTABLES = (
    "umount",
    "isoinfo",
    "fuseiso",
    "squashfuse",
    "gost12sum",
)

# altrepodb.spdx
SPDX_URL = "https://github.com/spdx/license-list-data"
SPDX_GIT_ROOT = "SPDX"
SPDX_LICENSES = "json/details"
SPDX_EXCEPTIONS = "json/exceptions"
SPDX_GIT_CLONE_TIMEOUT = 60
SPDX_GIT_PULL_TIMEOUT = 60 * 5

BUGZILLA_URL = "https://bugzilla.altlinux.org/buglist.cgi"
WATCH_URL = "https://watch.altlinux.org/pub/watch/watch-total.txt"
REPOCOP_URL = "http://repocop.altlinux.org/pub/repocop/prometheus3/packages.altlinux-sisyphus.json.bz2"
