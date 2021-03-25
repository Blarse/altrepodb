import os
import rpm

from utils import changelog_to_text, cvt, cvt_ts, packager_parse, mmhash


os.environ['LANG'] = 'C'


def detect_arch(hdr):
    package_name = cvt(hdr[rpm.RPMTAG_NAME])
    if package_name.startswith('i586-'):
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
        'pkg_hash': mmhash(bytes.fromhex(cvt(hdr[rpm.RPMDBI_SHA1HEADER]))),
        'pkg_cs': bytes.fromhex(cvt(hdr[rpm.RPMDBI_SHA1HEADER])),
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
        'pkg_changelog': changelog_to_text(
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
        'filename': cvt(hdr[rpm.RPMTAG_FILENAMES]),
        'filelinkto': cvt(hdr[rpm.RPMTAG_FILELINKTOS]),
        'filemd5': cvt(hdr[rpm.RPMTAG_FILEMD5S]),
        'filesize': cvt(hdr[rpm.RPMTAG_FILESIZES]),
        'filemode': cvt(hdr[rpm.RPMTAG_FILEMODES]),
        'filerdev': cvt(hdr[rpm.RPMTAG_FILERDEVS]),
        'filemtime': cvt_ts(hdr[rpm.RPMTAG_FILEMTIMES]),
        'fileflag': cvt(hdr[rpm.RPMTAG_FILEFLAGS]),
        'fileusername': cvt(hdr[rpm.RPMTAG_FILEUSERNAME]),
        'filegroupname': cvt(hdr[rpm.RPMTAG_FILEGROUPNAME]),
        'fileverifyflag': cvt(hdr[rpm.RPMTAG_FILEVERIFYFLAGS]),
        'filedevice': cvt(hdr[rpm.RPMTAG_FILEDEVICES]),
        'filelang': cvt(hdr[rpm.RPMTAG_FILELANGS]),
        'fileclass': cvt(hdr[rpm.RPMTAG_FILECLASS]),
    }
    return map_files


def get_require_map(hdr):
    map_require = {
        'dpname': cvt(hdr[rpm.RPMTAG_REQUIRENAME]),
        'dpversion': cvt(hdr[rpm.RPMTAG_REQUIREVERSION]),
        'flag': hdr[rpm.RPMTAG_REQUIREFLAGS],
    }
    return map_require


def get_conflict_map(hdr):
    map_conflict = {
        'dpname': cvt(hdr[rpm.RPMTAG_CONFLICTNAME]),
        'dpversion': cvt(hdr[rpm.RPMTAG_CONFLICTVERSION]),
        'flag': hdr[rpm.RPMTAG_CONFLICTFLAGS],
    }
    return map_conflict


def get_obsolete_map(hdr):
    map_obsolete = {
        'dpname': cvt(hdr[rpm.RPMTAG_OBSOLETENAME]),
        'dpversion': cvt(hdr[rpm.RPMTAG_OBSOLETEVERSION]),
        'flag': hdr[rpm.RPMTAG_OBSOLETEFLAGS],
    }
    return map_obsolete


def get_provide_map(hdr):
    map_provide = {
        'dpname': cvt(hdr[rpm.RPMTAG_PROVIDENAME]),
        'dpversion': cvt(hdr[rpm.RPMTAG_PROVIDEVERSION]),
        'flag': hdr[rpm.RPMTAG_PROVIDEFLAGS],
    }
    return map_provide
