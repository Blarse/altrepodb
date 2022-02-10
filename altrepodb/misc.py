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

from dataclasses import dataclass

@dataclass(frozen=True)
class LookUpTable:
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
    BEEHIVE_BASE_URL = "http://git.altlinux.org/beehive"
    BEEHIVE_BRANCHES = (
        "Sisyphus",
        "p10",
        "p9",
    )
    BEEHIVE_ARCHS = ("i586", "x86_64")
    BUGZILLA_URL = "https://bugzilla.altlinux.org/buglist.cgi"
    URL_WATCH = "https://watch.altlinux.org/pub/watch/watch-total.txt"
    URL_REPOCOP = "http://repocop.altlinux.org/pub/repocop/prometheus3/packages.altlinux-sisyphus.json.bz2"


lut = LookUpTable()
