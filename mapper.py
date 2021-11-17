import os

from utils import changelog_to_list, cvt, cvt_ts, packager_parse, snowflake_id, convert_file_class


os.environ['LANG'] = 'C'


def detect_arch(hdr):
    package_name = cvt(hdr["RPMTAG_NAME"])
    if package_name.startswith('i586-'):
        return 'x86_64-i586'

    return cvt(hdr["RPMTAG_ARCH"])


def get_package_map(hdr):
    packager = cvt(hdr["RPMTAG_PACKAGER"])
    name_email = packager_parse(packager)
    if name_email:
        pname, pemail = name_email
    else:
        pname, pemail = packager, ''

    map_package = {
        'pkg_hash': snowflake_id(hdr),
        'pkg_cs': bytes.fromhex(cvt(hdr["RPMSIGTAG_SHA1"])),
        'pkg_packager': pname,
        'pkg_packager_email': pemail,
        'pkg_name': cvt(hdr["RPMTAG_NAME"]),
        'pkg_arch': detect_arch(hdr),
        'pkg_version': cvt(hdr["RPMTAG_VERSION"]),
        'pkg_release': cvt(hdr["RPMTAG_RELEASE"]),
        'pkg_epoch': cvt(hdr["RPMTAG_EPOCH"], int),
        'pkg_serial_': cvt(hdr["RPMTAG_SERIAL"], int),
        'pkg_buildtime': cvt(hdr["RPMTAG_BUILDTIME"]),
        'pkg_buildhost': cvt(hdr["RPMTAG_BUILDHOST"]),
        'pkg_size': cvt(hdr["RPMTAG_SIZE"], int),
        'pkg_archivesize': cvt(hdr["RPMTAG_ARCHIVESIZE"]),
        'pkg_rpmversion': cvt(hdr["RPMTAG_RPMVERSION"]),
        'pkg_cookie': cvt(hdr["RPMTAG_COOKIE"]),
        'pkg_sourcepackage': int(bool(hdr["RPMTAG_SOURCEPACKAGE"])),
        'pkg_disttag': cvt(hdr["RPMTAG_DISTTAG"]),
        'pkg_sourcerpm': cvt(hdr["RPMTAG_SOURCERPM"]),
        'pkg_summary': cvt(hdr["RPMTAG_SUMMARY"]),
        'pkg_description': cvt(hdr["RPMTAG_DESCRIPTION"]),
        'pkg_changelog': changelog_to_list(
            hdr["RPMTAG_CHANGELOGTIME"],
            hdr["RPMTAG_CHANGELOGNAME"],
            hdr["RPMTAG_CHANGELOGTEXT"]),
        'pkg_distribution': cvt(hdr["RPMTAG_DISTRIBUTION"]),
        'pkg_vendor': cvt(hdr["RPMTAG_VENDOR"]),
        'pkg_gif': cvt(hdr["RPMTAG_GIF"], bytes),
        'pkg_xpm': cvt(hdr["RPMTAG_XPM"], bytes),
        'pkg_license': cvt(hdr["RPMTAG_LICENSE"]),
        'pkg_group_': cvt(hdr["RPMTAG_GROUP"]),
        'pkg_url': cvt(hdr["RPMTAG_URL"]),
        'pkg_os': cvt(hdr["RPMTAG_OS"]),
        'pkg_prein': cvt(hdr["RPMTAG_PREIN"]),
        'pkg_postin': cvt(hdr["RPMTAG_POSTIN"]),
        'pkg_preun': cvt(hdr["RPMTAG_PREUN"]),
        'pkg_postun': cvt(hdr["RPMTAG_POSTUN"]),
        'pkg_icon': cvt(hdr["RPMTAG_ICON"], bytes),
        'pkg_preinprog': cvt(hdr["RPMTAG_PREINPROG"]),
        'pkg_postinprog': cvt(hdr["RPMTAG_POSTINPROG"]),
        'pkg_preunprog': cvt(hdr["RPMTAG_PREUNPROG"]),
        'pkg_postunprog': cvt(hdr["RPMTAG_POSTUNPROG"]),
        'pkg_buildarchs': cvt(hdr["RPMTAG_BUILDARCHS"]),
        'pkg_verifyscript': cvt(hdr["RPMTAG_VERIFYSCRIPT"]),
        'pkg_verifyscriptprog': cvt(hdr["RPMTAG_VERIFYSCRIPTPROG"]),
        'pkg_prefixes': cvt(hdr["RPMTAG_PREFIXES"]),
        'pkg_instprefixes': cvt(hdr["RPMTAG_INSTPREFIXES"]),
        'pkg_optflags': cvt(hdr["RPMTAG_OPTFLAGS"]),
        'pkg_disturl': cvt(hdr["RPMTAG_DISTURL"]),
        'pkg_payloadformat': cvt(hdr["RPMTAG_PAYLOADFORMAT"]),
        'pkg_payloadcompressor': cvt(hdr["RPMTAG_PAYLOADCOMPRESSOR"]),
        'pkg_payloadflags': cvt(hdr["RPMTAG_PAYLOADFLAGS"]),
        'pkg_platform': cvt(hdr["RPMTAG_PLATFORM"]),
    }
    return map_package


def get_file_map(hdr):
    map_files = {
        'file_name': cvt(hdr["RPMTAG_FILENAMES"]),
        'file_linkto': cvt(hdr["RPMTAG_FILELINKTOS"]),
        'file_md5':  cvt(hdr["RPMTAG_FILEMD5S"]),
        'file_size': cvt(hdr["RPMTAG_FILESIZES"]),
        'file_mode': cvt(hdr["RPMTAG_FILEMODES"]),
        'file_rdev': cvt(hdr["RPMTAG_FILERDEVS"]),
        'file_mtime': cvt_ts(hdr["RPMTAG_FILEMTIMES"]),
        'file_flag': cvt(hdr["RPMTAG_FILEFLAGS"]),
        'file_username': cvt(hdr["RPMTAG_FILEUSERNAME"]),
        'file_groupname': cvt(hdr["RPMTAG_FILEGROUPNAME"]),
        'file_verifyflag': cvt(hdr["RPMTAG_FILEVERIFYFLAGS"]),
        'file_device': cvt(hdr["RPMTAG_FILEDEVICES"]),
        'file_lang': cvt(hdr["RPMTAG_FILELANGS"]),
        'file_class': cvt(hdr["RPMTAG_FILECLASS"])
    }
    # convert MD5 to bytes and 'file_class' to CH Enum set
    map_files['file_md5'] = [bytes.fromhex(v) for v in map_files['file_md5']]
    map_files['file_class'] = [convert_file_class(v) for v in map_files['file_class']]
    return map_files


def get_require_map(hdr):
    map_require = {
        'dp_name': cvt(hdr["RPMTAG_REQUIRENAME"]),
        'dp_version': cvt(hdr["RPMTAG_REQUIREVERSION"]),
        'dp_flag': hdr["RPMTAG_REQUIREFLAGS"],
    }
    return map_require


def get_conflict_map(hdr):
    map_conflict = {
        'dp_name': cvt(hdr["RPMTAG_CONFLICTNAME"]),
        'dp_version': cvt(hdr["RPMTAG_CONFLICTVERSION"]),
        'dp_flag': hdr["RPMTAG_CONFLICTFLAGS"],
    }
    return map_conflict


def get_obsolete_map(hdr):
    map_obsolete = {
        'dp_name': cvt(hdr["RPMTAG_OBSOLETENAME"]),
        'dp_version': cvt(hdr["RPMTAG_OBSOLETEVERSION"]),
        'dp_flag': hdr["RPMTAG_OBSOLETEFLAGS"],
    }
    return map_obsolete


def get_provide_map(hdr):
    map_provide = {
        'dp_name': cvt(hdr["RPMTAG_PROVIDENAME"]),
        'dp_version': cvt(hdr["RPMTAG_PROVIDEVERSION"]),
        'dp_flag': hdr["RPMTAG_PROVIDEFLAGS"],
    }
    return map_provide
