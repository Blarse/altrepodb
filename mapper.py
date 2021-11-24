import os

from altrpm import rpm
from utils import changelog_to_list, cvt, cvt_ts, packager_parse, snowflake_id, convert_file_class


os.environ['LANG'] = 'C'


def detect_arch(hdr):
    package_name = cvt(hdr[rpm.RPMTAG_NAME])
    if package_name.startswith('i586-'):  # type: ignore
        return 'x86_64-i586'

    return cvt(hdr[rpm.RPMTAG_ARCH])


def get_package_map(hdr):
    packager = cvt(hdr[rpm.RPMTAG_PACKAGER])
    name_email = packager_parse(packager)
    if name_email:
        pname, pemail = name_email
    else:
        pname, pemail = packager, ''

    map_package = {
        'pkg_hash': snowflake_id(hdr),
        'pkg_cs': bytes.fromhex(cvt(hdr[rpm.RPMTAG_SHA1HEADER])),  # type: ignore
        'pkg_packager': pname,
        'pkg_packager_email': pemail,
        'pkg_name': cvt(hdr[rpm.RPMTAG_NAME]),
        'pkg_arch': detect_arch(hdr),
        'pkg_version': cvt(hdr[rpm.RPMTAG_VERSION]),
        'pkg_release': cvt(hdr[rpm.RPMTAG_RELEASE]),
        'pkg_epoch': cvt(hdr[rpm.RPMTAG_EPOCH], int),
        'pkg_serial_': cvt(hdr[rpm.RPMTAG_SERIAL], int),
        'pkg_buildtime': cvt(hdr[rpm.RPMTAG_BUILDTIME]),
        'pkg_buildhost': cvt(hdr[rpm.RPMTAG_BUILDHOST]),
        'pkg_size': cvt(hdr[rpm.RPMTAG_SIZE], int),
        'pkg_archivesize': cvt(hdr[rpm.RPMTAG_ARCHIVESIZE]),
        'pkg_rpmversion': cvt(hdr[rpm.RPMTAG_RPMVERSION]),
        'pkg_cookie': cvt(hdr[rpm.RPMTAG_COOKIE]),
        'pkg_sourcepackage': int(bool(hdr[rpm.RPMTAG_SOURCEPACKAGE])),
        'pkg_disttag': cvt(hdr[rpm.RPMTAG_DISTTAG]),
        'pkg_sourcerpm': cvt(hdr[rpm.RPMTAG_SOURCERPM]),
        'pkg_summary': cvt(hdr[rpm.RPMTAG_SUMMARY]),
        'pkg_description': cvt(hdr[rpm.RPMTAG_DESCRIPTION]),
        'pkg_changelog': changelog_to_list(
            hdr[rpm.RPMTAG_CHANGELOGTIME],
            hdr[rpm.RPMTAG_CHANGELOGNAME],
            hdr[rpm.RPMTAG_CHANGELOGTEXT]),
        'pkg_distribution': cvt(hdr[rpm.RPMTAG_DISTRIBUTION]),
        'pkg_vendor': cvt(hdr[rpm.RPMTAG_VENDOR]),
        'pkg_gif': cvt(hdr[rpm.RPMTAG_GIF], bytes),
        'pkg_xpm': cvt(hdr[rpm.RPMTAG_XPM], bytes),
        'pkg_license': cvt(hdr[rpm.RPMTAG_LICENSE]),
        'pkg_group_': cvt(hdr[rpm.RPMTAG_GROUP]),
        'pkg_url': cvt(hdr[rpm.RPMTAG_URL]),
        'pkg_os': cvt(hdr[rpm.RPMTAG_OS]),
        'pkg_prein': cvt(hdr[rpm.RPMTAG_PREIN]),
        'pkg_postin': cvt(hdr[rpm.RPMTAG_POSTIN]),
        'pkg_preun': cvt(hdr[rpm.RPMTAG_PREUN]),
        'pkg_postun': cvt(hdr[rpm.RPMTAG_POSTUN]),
        'pkg_icon': cvt(hdr[rpm.RPMTAG_ICON], bytes),
        'pkg_preinprog': cvt(hdr[rpm.RPMTAG_PREINPROG]),
        'pkg_postinprog': cvt(hdr[rpm.RPMTAG_POSTINPROG]),
        'pkg_preunprog': cvt(hdr[rpm.RPMTAG_PREUNPROG]),
        'pkg_postunprog': cvt(hdr[rpm.RPMTAG_POSTUNPROG]),
        'pkg_buildarchs': cvt(hdr[rpm.RPMTAG_BUILDARCHS]),
        'pkg_verifyscript': cvt(hdr[rpm.RPMTAG_VERIFYSCRIPT]),
        'pkg_verifyscriptprog': cvt(hdr[rpm.RPMTAG_VERIFYSCRIPTPROG]),
        'pkg_prefixes': cvt(hdr[rpm.RPMTAG_PREFIXES]),
        'pkg_instprefixes': cvt(hdr[rpm.RPMTAG_INSTPREFIXES]),
        'pkg_optflags': cvt(hdr[rpm.RPMTAG_OPTFLAGS]),
        'pkg_disturl': cvt(hdr[rpm.RPMTAG_DISTURL]),
        'pkg_payloadformat': cvt(hdr[rpm.RPMTAG_PAYLOADFORMAT]),
        'pkg_payloadcompressor': cvt(hdr[rpm.RPMTAG_PAYLOADCOMPRESSOR]),
        'pkg_payloadflags': cvt(hdr[rpm.RPMTAG_PAYLOADFLAGS]),
        'pkg_platform': cvt(hdr[rpm.RPMTAG_PLATFORM]),
    }
    return map_package


def get_file_map(hdr):
    map_files = {
        'file_name': cvt(hdr[rpm.RPMTAG_FILENAMES]),
        'file_linkto': cvt(hdr[rpm.RPMTAG_FILELINKTOS]),
        'file_md5':  cvt(hdr[rpm.RPMTAG_FILEMD5S]),
        'file_size': cvt(hdr[rpm.RPMTAG_FILESIZES]),
        'file_mode': cvt(hdr[rpm.RPMTAG_FILEMODES]),
        'file_rdev': cvt(hdr[rpm.RPMTAG_FILERDEVS]),
        'file_mtime': cvt_ts(hdr[rpm.RPMTAG_FILEMTIMES]),
        'file_flag': cvt(hdr[rpm.RPMTAG_FILEFLAGS]),
        'file_username': cvt(hdr[rpm.RPMTAG_FILEUSERNAME]),
        'file_groupname': cvt(hdr[rpm.RPMTAG_FILEGROUPNAME]),
        'file_verifyflag': cvt(hdr[rpm.RPMTAG_FILEVERIFYFLAGS]),
        'file_device': cvt(hdr[rpm.RPMTAG_FILEDEVICES]),
        'file_lang': cvt(hdr[rpm.RPMTAG_FILELANGS]),
        'file_class': cvt(hdr[rpm.RPMTAG_FILECLASS])
    }
    # convert MD5 to bytes and 'file_class' to CH Enum set
    map_files['file_md5'] = [bytes.fromhex(v) for v in map_files['file_md5']]
    map_files['file_class'] = [convert_file_class(v) for v in map_files['file_class']]
    return map_files


def get_require_map(hdr):
    map_require = {
        'dp_name': cvt(hdr[rpm.RPMTAG_REQUIRENAME]),
        'dp_version': cvt(hdr[rpm.RPMTAG_REQUIREVERSION]),
        'dp_flag': hdr[rpm.RPMTAG_REQUIREFLAGS],
    }
    return map_require


def get_conflict_map(hdr):
    map_conflict = {
        'dp_name': cvt(hdr[rpm.RPMTAG_CONFLICTNAME]),
        'dp_version': cvt(hdr[rpm.RPMTAG_CONFLICTVERSION]),
        'dp_flag': hdr[rpm.RPMTAG_CONFLICTFLAGS],
    }
    return map_conflict


def get_obsolete_map(hdr):
    map_obsolete = {
        'dp_name': cvt(hdr[rpm.RPMTAG_OBSOLETENAME]),
        'dp_version': cvt(hdr[rpm.RPMTAG_OBSOLETEVERSION]),
        'dp_flag': hdr[rpm.RPMTAG_OBSOLETEFLAGS],
    }
    return map_obsolete


def get_provide_map(hdr):
    map_provide = {
        'dp_name': cvt(hdr[rpm.RPMTAG_PROVIDENAME]),
        'dp_version': cvt(hdr[rpm.RPMTAG_PROVIDEVERSION]),
        'dp_flag': hdr[rpm.RPMTAG_PROVIDEFLAGS],
    }
    return map_provide
