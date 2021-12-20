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

import os

from altrpm import rpm as rpmt
from .utils import (
    cvt,
    cvt_ts,
    detect_arch,
    packager_parse,
    snowflake_id_pkg,
    changelog_to_list,
    convert_file_class,
)


os.environ["LANG"] = "C"


def unpack_map(tagmap):
    return [dict(zip(tagmap, v)) for v in zip(*tagmap.values())]


def get_package_map(hdr):
    packager = cvt(hdr[rpmt.RPMTAG_PACKAGER])
    name_email = packager_parse(packager)
    if name_email:
        pname, pemail = name_email
    else:
        pname, pemail = packager, ""

    map_package = {
        "pkg_hash": snowflake_id_pkg(hdr),
        "pkg_cs": bytes.fromhex(cvt(hdr[rpmt.RPMTAG_SHA1HEADER])),  # type: ignore
        "pkg_packager": pname,
        "pkg_packager_email": pemail,
        "pkg_name": cvt(hdr[rpmt.RPMTAG_NAME]),
        "pkg_arch": detect_arch(hdr),
        "pkg_version": cvt(hdr[rpmt.RPMTAG_VERSION]),
        "pkg_release": cvt(hdr[rpmt.RPMTAG_RELEASE]),
        "pkg_epoch": cvt(hdr[rpmt.RPMTAG_EPOCH], int),
        "pkg_serial_": cvt(hdr[rpmt.RPMTAG_SERIAL], int),
        "pkg_buildtime": cvt(hdr[rpmt.RPMTAG_BUILDTIME]),
        "pkg_buildhost": cvt(hdr[rpmt.RPMTAG_BUILDHOST]),
        "pkg_size": cvt(hdr[rpmt.RPMTAG_SIZE], int),
        "pkg_archivesize": cvt(hdr[rpmt.RPMTAG_ARCHIVESIZE]),
        "pkg_rpmversion": cvt(hdr[rpmt.RPMTAG_RPMVERSION]),
        "pkg_cookie": cvt(hdr[rpmt.RPMTAG_COOKIE]),
        "pkg_sourcepackage": int(bool(hdr[rpmt.RPMTAG_SOURCEPACKAGE])),
        "pkg_disttag": cvt(hdr[rpmt.RPMTAG_DISTTAG]),
        "pkg_sourcerpm": cvt(hdr[rpmt.RPMTAG_SOURCERPM]),
        "pkg_summary": cvt(hdr[rpmt.RPMTAG_SUMMARY]),
        "pkg_description": cvt(hdr[rpmt.RPMTAG_DESCRIPTION]),
        "pkg_changelog": changelog_to_list(
            hdr[rpmt.RPMTAG_CHANGELOGTIME],
            hdr[rpmt.RPMTAG_CHANGELOGNAME],
            hdr[rpmt.RPMTAG_CHANGELOGTEXT],
        ),
        "pkg_distribution": cvt(hdr[rpmt.RPMTAG_DISTRIBUTION]),
        "pkg_vendor": cvt(hdr[rpmt.RPMTAG_VENDOR]),
        "pkg_gif": cvt(hdr[rpmt.RPMTAG_GIF], bytes),
        "pkg_xpm": cvt(hdr[rpmt.RPMTAG_XPM], bytes),
        "pkg_license": cvt(hdr[rpmt.RPMTAG_LICENSE]),
        "pkg_group_": cvt(hdr[rpmt.RPMTAG_GROUP]),
        "pkg_url": cvt(hdr[rpmt.RPMTAG_URL]),
        "pkg_os": cvt(hdr[rpmt.RPMTAG_OS]),
        "pkg_prein": cvt(hdr[rpmt.RPMTAG_PREIN]),
        "pkg_postin": cvt(hdr[rpmt.RPMTAG_POSTIN]),
        "pkg_preun": cvt(hdr[rpmt.RPMTAG_PREUN]),
        "pkg_postun": cvt(hdr[rpmt.RPMTAG_POSTUN]),
        "pkg_icon": cvt(hdr[rpmt.RPMTAG_ICON], bytes),
        "pkg_preinprog": cvt(hdr[rpmt.RPMTAG_PREINPROG]),
        "pkg_postinprog": cvt(hdr[rpmt.RPMTAG_POSTINPROG]),
        "pkg_preunprog": cvt(hdr[rpmt.RPMTAG_PREUNPROG]),
        "pkg_postunprog": cvt(hdr[rpmt.RPMTAG_POSTUNPROG]),
        "pkg_buildarchs": cvt(hdr[rpmt.RPMTAG_BUILDARCHS]),
        "pkg_verifyscript": cvt(hdr[rpmt.RPMTAG_VERIFYSCRIPT]),
        "pkg_verifyscriptprog": cvt(hdr[rpmt.RPMTAG_VERIFYSCRIPTPROG]),
        "pkg_prefixes": cvt(hdr[rpmt.RPMTAG_PREFIXES]),
        "pkg_instprefixes": cvt(hdr[rpmt.RPMTAG_INSTPREFIXES]),
        "pkg_optflags": cvt(hdr[rpmt.RPMTAG_OPTFLAGS]),
        "pkg_disturl": cvt(hdr[rpmt.RPMTAG_DISTURL]),
        "pkg_payloadformat": cvt(hdr[rpmt.RPMTAG_PAYLOADFORMAT]),
        "pkg_payloadcompressor": cvt(hdr[rpmt.RPMTAG_PAYLOADCOMPRESSOR]),
        "pkg_payloadflags": cvt(hdr[rpmt.RPMTAG_PAYLOADFLAGS]),
        "pkg_platform": cvt(hdr[rpmt.RPMTAG_PLATFORM]),
    }
    return map_package


def get_partial_pkg_map(hdr, key_list):
    map_package = get_package_map(hdr)
    res = {}
    for key in key_list:
        res[key] = map_package[key]
    return res


def get_file_map(hdr):
    map_files = {
        "file_name": cvt(hdr[rpmt.RPMTAG_FILENAMES]),
        "file_linkto": cvt(hdr[rpmt.RPMTAG_FILELINKTOS]),
        "file_md5": cvt(hdr[rpmt.RPMTAG_FILEMD5S]),
        "file_size": cvt(hdr[rpmt.RPMTAG_FILESIZES]),
        "file_mode": cvt(hdr[rpmt.RPMTAG_FILEMODES]),
        "file_rdev": cvt(hdr[rpmt.RPMTAG_FILERDEVS]),
        "file_mtime": cvt_ts(hdr[rpmt.RPMTAG_FILEMTIMES]),
        "file_flag": cvt(hdr[rpmt.RPMTAG_FILEFLAGS]),
        "file_username": cvt(hdr[rpmt.RPMTAG_FILEUSERNAME]),
        "file_groupname": cvt(hdr[rpmt.RPMTAG_FILEGROUPNAME]),
        "file_verifyflag": cvt(hdr[rpmt.RPMTAG_FILEVERIFYFLAGS]),
        "file_device": cvt(hdr[rpmt.RPMTAG_FILEDEVICES]),
        "file_lang": cvt(hdr[rpmt.RPMTAG_FILELANGS]),
        "file_class": cvt(hdr[rpmt.RPMTAG_FILECLASS]),
    }
    # convert MD5 to bytes and 'file_class' to CH Enum set
    map_files["file_md5"] = [bytes.fromhex(v) for v in map_files["file_md5"]]
    map_files["file_class"] = [convert_file_class(v) for v in map_files["file_class"]]
    return map_files


def get_require_map(hdr):
    map_require = {
        "dp_name": cvt(hdr[rpmt.RPMTAG_REQUIRENAME]),
        "dp_version": cvt(hdr[rpmt.RPMTAG_REQUIREVERSION]),
        "dp_flag": hdr[rpmt.RPMTAG_REQUIREFLAGS],
    }
    return map_require


def get_conflict_map(hdr):
    map_conflict = {
        "dp_name": cvt(hdr[rpmt.RPMTAG_CONFLICTNAME]),
        "dp_version": cvt(hdr[rpmt.RPMTAG_CONFLICTVERSION]),
        "dp_flag": hdr[rpmt.RPMTAG_CONFLICTFLAGS],
    }
    return map_conflict


def get_obsolete_map(hdr):
    map_obsolete = {
        "dp_name": cvt(hdr[rpmt.RPMTAG_OBSOLETENAME]),
        "dp_version": cvt(hdr[rpmt.RPMTAG_OBSOLETEVERSION]),
        "dp_flag": hdr[rpmt.RPMTAG_OBSOLETEFLAGS],
    }
    return map_obsolete


def get_provide_map(hdr):
    map_provide = {
        "dp_name": cvt(hdr[rpmt.RPMTAG_PROVIDENAME]),
        "dp_version": cvt(hdr[rpmt.RPMTAG_PROVIDEVERSION]),
        "dp_flag": hdr[rpmt.RPMTAG_PROVIDEFLAGS],
    }
    return map_provide
