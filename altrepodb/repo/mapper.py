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

import os
import mmh3
from typing import Any, Union
from collections import namedtuple

from altrpm import rpm as rpmt

from .utils import (
    mmhash,
    convert,
    convert_timestamp,
    parse_packager,
    snowflake_id,
)

os.environ["LANG"] = "C"

# rpm header type alias
rpm_header = dict[Any, Any]


ChangelogRecord = namedtuple("ChangelogRecord", ["date", "name", "evr", "text", "hash"])


def detect_arch(hdr: rpm_header) -> str:
    """Converts package architecture from header."""

    package_name = convert(hdr[rpmt.RPMTAG_NAME])
    if package_name.startswith("i586-"):
        return "x86_64-i586"
    return convert(hdr[rpmt.RPMTAG_ARCH])


def convert_file_class(file_class: str) -> str:
    """Converts file class value from RPM header to DB Enum."""

    lut = {
        "directory": "directory",
        "symbolic link to": "symlink",
        "socket": "socket",
        "character special": "char",
        "block special": "block",
        "fifo (named pipe)": "fifo",
        "file": "file",
    }
    if file_class == "":
        return lut["file"]
    else:
        for k, v in lut.items():
            if file_class.startswith(k):
                return v
    return ""


def changelog_to_list(dates: list, names: list, texts: list) -> list[ChangelogRecord]:
    """Compiles changelog records to list of parsed elements."""

    if not len(dates) == len(names) == len(texts):
        raise ValueError
    chlog = []
    for date_, name_, text_ in zip(dates, names, texts):
        tmp = convert(name_)
        text = convert(text_)
        # split original changelog name for `name` and `EVR` parts
        if len(tmp.split(">")) == 2:
            name = tmp.split(">")[0] + ">"
            evr = tmp.split(">")[1].strip()
        else:
            name = tmp
            evr = ""
        chlog.append(ChangelogRecord(int(date_), name, evr, text, mmhash(text)))
    return chlog


def snowflake_id_pkg(hdr: rpm_header, epoch: int = 1_000_000_000) -> int:
    """Genarates showflake-like ID using data from RPM package header object.
    Returns 64 bit wide unsigned integer:
        - most significant 32 bits package build time delta from epoch
        - less significant 32 bits are mutmurHash from package sign header (SHA1 + MD5 + GPG)

    Args:
        hdr (dict): RPM package header object
        epoch (int, optional): Base epoch for timestamp part calculation. Defaults to 1_000_000_000.

    Returns:
        int: showflake like ID
    """

    buildtime: int = cvt(hdr[rpmt.RPMTAG_BUILDTIME], int)  # type: ignore
    sha1: bytes = bytes.fromhex(cvt(hdr[rpmt.RPMTAG_SHA1HEADER]))  # type: ignore
    md5: bytes = hdr[rpmt.RPMTAG_SIGMD5]  # bytes
    gpg: bytes = hdr[rpmt.RPMTAG_SIGGPG]  # bytes

    if md5 is None:
        md5 = b""
    if gpg is None:
        gpg = b""
    # combine multiple GPG signs in one
    if isinstance(gpg, list):
        gpg_ = b""
        for k in gpg:
            gpg_ += k  # type: ignore
        gpg = gpg_

    data = sha1 + md5 + gpg
    sf_hash = mmh3.hash(data, signed=False)
    return snowflake_id(timestamp=buildtime, lower_32bit=sf_hash, epoch=epoch)


def unpack_map(tagmap: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(zip(tagmap, v)) for v in zip(*tagmap.values())]


def get_package_map(hdr: rpm_header) -> dict[str, Any]:
    packager = convert(hdr[rpmt.RPMTAG_PACKAGER])
    name_email = parse_packager(packager)
    if name_email:
        pname, pemail = name_email
    else:
        pname, pemail = packager, ""

    map_package = {
        "pkg_hash": snowflake_id_pkg(hdr),
        "pkg_cs": bytes.fromhex(convert(hdr[rpmt.RPMTAG_SHA1HEADER])),  # type: ignore
        "pkg_packager": pname,
        "pkg_packager_email": pemail,
        "pkg_name": convert(hdr[rpmt.RPMTAG_NAME]),
        "pkg_arch": detect_arch(hdr),
        "pkg_version": convert(hdr[rpmt.RPMTAG_VERSION]),
        "pkg_release": convert(hdr[rpmt.RPMTAG_RELEASE]),
        "pkg_epoch": convert(hdr[rpmt.RPMTAG_EPOCH], int),
        "pkg_serial_": convert(hdr[rpmt.RPMTAG_SERIAL], int),
        "pkg_buildtime": convert(hdr[rpmt.RPMTAG_BUILDTIME]),
        "pkg_buildhost": convert(hdr[rpmt.RPMTAG_BUILDHOST]),
        "pkg_size": convert(hdr[rpmt.RPMTAG_SIZE], int),
        "pkg_archivesize": convert(hdr[rpmt.RPMTAG_ARCHIVESIZE]),
        "pkg_rpmversion": convert(hdr[rpmt.RPMTAG_RPMVERSION]),
        "pkg_cookie": convert(hdr[rpmt.RPMTAG_COOKIE]),
        "pkg_sourcepackage": int(bool(hdr[rpmt.RPMTAG_SOURCEPACKAGE])),
        "pkg_disttag": convert(hdr[rpmt.RPMTAG_DISTTAG]),
        "pkg_sourcerpm": convert(hdr[rpmt.RPMTAG_SOURCERPM]),
        "pkg_summary": convert(hdr[rpmt.RPMTAG_SUMMARY]),
        "pkg_description": convert(hdr[rpmt.RPMTAG_DESCRIPTION]),
        "pkg_changelog": changelog_to_list(
            hdr[rpmt.RPMTAG_CHANGELOGTIME],
            hdr[rpmt.RPMTAG_CHANGELOGNAME],
            hdr[rpmt.RPMTAG_CHANGELOGTEXT],
        ),
        "pkg_distribution": convert(hdr[rpmt.RPMTAG_DISTRIBUTION]),
        "pkg_vendor": convert(hdr[rpmt.RPMTAG_VENDOR]),
        "pkg_gif": convert(hdr[rpmt.RPMTAG_GIF], bytes),
        "pkg_xpm": convert(hdr[rpmt.RPMTAG_XPM], bytes),
        "pkg_license": convert(hdr[rpmt.RPMTAG_LICENSE]),
        "pkg_group_": convert(hdr[rpmt.RPMTAG_GROUP]),
        "pkg_url": convert(hdr[rpmt.RPMTAG_URL]),
        "pkg_os": convert(hdr[rpmt.RPMTAG_OS]),
        "pkg_prein": convert(hdr[rpmt.RPMTAG_PREIN]),
        "pkg_postin": convert(hdr[rpmt.RPMTAG_POSTIN]),
        "pkg_preun": convert(hdr[rpmt.RPMTAG_PREUN]),
        "pkg_postun": convert(hdr[rpmt.RPMTAG_POSTUN]),
        "pkg_icon": convert(hdr[rpmt.RPMTAG_ICON], bytes),
        "pkg_preinprog": convert(hdr[rpmt.RPMTAG_PREINPROG]),
        "pkg_postinprog": convert(hdr[rpmt.RPMTAG_POSTINPROG]),
        "pkg_preunprog": convert(hdr[rpmt.RPMTAG_PREUNPROG]),
        "pkg_postunprog": convert(hdr[rpmt.RPMTAG_POSTUNPROG]),
        "pkg_buildarchs": convert(hdr[rpmt.RPMTAG_BUILDARCHS]),
        "pkg_verifyscript": convert(hdr[rpmt.RPMTAG_VERIFYSCRIPT]),
        "pkg_verifyscriptprog": convert(hdr[rpmt.RPMTAG_VERIFYSCRIPTPROG]),
        "pkg_prefixes": convert(hdr[rpmt.RPMTAG_PREFIXES]),
        "pkg_instprefixes": convert(hdr[rpmt.RPMTAG_INSTPREFIXES]),
        "pkg_optflags": convert(hdr[rpmt.RPMTAG_OPTFLAGS]),
        "pkg_disturl": convert(hdr[rpmt.RPMTAG_DISTURL]),
        "pkg_payloadformat": convert(hdr[rpmt.RPMTAG_PAYLOADFORMAT]),
        "pkg_payloadcompressor": convert(hdr[rpmt.RPMTAG_PAYLOADCOMPRESSOR]),
        "pkg_payloadflags": convert(hdr[rpmt.RPMTAG_PAYLOADFLAGS]),
        "pkg_platform": convert(hdr[rpmt.RPMTAG_PLATFORM]),
    }
    return map_package


def get_partial_pkg_map(hdr: rpm_header, key_list: Union[list[str], tuple[str,...]]) -> dict[str, Any]:
    map_package = get_package_map(hdr)
    res = {}
    for key in key_list:
        res[key] = map_package[key]
    return res


def get_file_map(hdr: rpm_header) -> dict[str, Any]:
    map_files = {
        "file_name": convert(hdr[rpmt.RPMTAG_FILENAMES]),
        "file_linkto": convert(hdr[rpmt.RPMTAG_FILELINKTOS]),
        "file_md5": convert(hdr[rpmt.RPMTAG_FILEMD5S]),
        "file_size": convert(hdr[rpmt.RPMTAG_FILESIZES]),
        "file_mode": convert(hdr[rpmt.RPMTAG_FILEMODES]),
        "file_rdev": convert(hdr[rpmt.RPMTAG_FILERDEVS]),
        "file_mtime": convert_timestamp(hdr[rpmt.RPMTAG_FILEMTIMES]),
        "file_flag": convert(hdr[rpmt.RPMTAG_FILEFLAGS]),
        "file_username": convert(hdr[rpmt.RPMTAG_FILEUSERNAME]),
        "file_groupname": convert(hdr[rpmt.RPMTAG_FILEGROUPNAME]),
        "file_verifyflag": convert(hdr[rpmt.RPMTAG_FILEVERIFYFLAGS]),
        "file_device": convert(hdr[rpmt.RPMTAG_FILEDEVICES]),
        "file_lang": convert(hdr[rpmt.RPMTAG_FILELANGS]),
        "file_class": convert(hdr[rpmt.RPMTAG_FILECLASS]),
    }
    # convert MD5 to bytes and 'file_class' to CH Enum set
    map_files["file_md5"] = [bytes.fromhex(v) for v in map_files["file_md5"]]
    map_files["file_class"] = [convert_file_class(v) for v in map_files["file_class"]]
    return map_files


def get_require_map(hdr: rpm_header) -> dict[str, Any]:
    map_require = {
        "dp_name": convert(hdr[rpmt.RPMTAG_REQUIRENAME]),
        "dp_version": convert(hdr[rpmt.RPMTAG_REQUIREVERSION]),
        "dp_flag": hdr[rpmt.RPMTAG_REQUIREFLAGS],
    }
    return map_require


def get_conflict_map(hdr: rpm_header) -> dict[str, Any]:
    map_conflict = {
        "dp_name": convert(hdr[rpmt.RPMTAG_CONFLICTNAME]),
        "dp_version": convert(hdr[rpmt.RPMTAG_CONFLICTVERSION]),
        "dp_flag": hdr[rpmt.RPMTAG_CONFLICTFLAGS],
    }
    return map_conflict


def get_obsolete_map(hdr: rpm_header) -> dict[str, Any]:
    map_obsolete = {
        "dp_name": convert(hdr[rpmt.RPMTAG_OBSOLETENAME]),
        "dp_version": convert(hdr[rpmt.RPMTAG_OBSOLETEVERSION]),
        "dp_flag": hdr[rpmt.RPMTAG_OBSOLETEFLAGS],
    }
    return map_obsolete


def get_provide_map(hdr: rpm_header) -> dict[str, Any]:
    map_provide = {
        "dp_name": convert(hdr[rpmt.RPMTAG_PROVIDENAME]),
        "dp_version": convert(hdr[rpmt.RPMTAG_PROVIDEVERSION]),
        "dp_flag": hdr[rpmt.RPMTAG_PROVIDEFLAGS],
    }
    return map_provide
