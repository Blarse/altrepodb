import rpm

from utils import changelog_to_text, cvt, cvt_ts, packager_parse, mmhash


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
        'pkghash': mmhash(cvt(hdr[rpm.RPMDBI_SHA1HEADER])),
        'pkgcs': cvt(hdr[rpm.RPMDBI_SHA1HEADER]),
        'packager': pname,
        'packager_email': pemail,
        'name': cvt(hdr[rpm.RPMTAG_NAME]),
        'arch': detect_arch(hdr),
        'version': cvt(hdr[rpm.RPMTAG_VERSION]),
        'release': cvt(hdr[rpm.RPMTAG_RELEASE]),
        'epoch': cvt(hdr[rpm.RPMTAG_EPOCH], int),
        'serial_': cvt(hdr[rpm.RPMTAG_SERIAL], int),
        'buildtime': cvt(hdr[rpm.RPMTAG_BUILDTIME]),
        'buildhost': cvt(hdr[rpm.RPMTAG_BUILDHOST]),
        'size': cvt(hdr[rpm.RPMTAG_SIZE], int),
        'archivesize': cvt(hdr[rpm.RPMTAG_ARCHIVESIZE]),
        'rpmversion': cvt(hdr[rpm.RPMTAG_RPMVERSION]),
        'cookie': cvt(hdr[rpm.RPMTAG_COOKIE]),
        'sourcepackage': int(bool(hdr[rpm.RPMTAG_SOURCEPACKAGE])),
        'disttag': cvt(hdr[rpm.RPMTAG_DISTTAG]),
        'sourcerpm': cvt(hdr[rpm.RPMTAG_SOURCERPM]),
        'summary': cvt(hdr[rpm.RPMTAG_SUMMARY]),
        'description': cvt(hdr[rpm.RPMTAG_DESCRIPTION]),
        'changelog': changelog_to_text(
            hdr[rpm.RPMTAG_CHANGELOGTIME],
            hdr[rpm.RPMTAG_CHANGELOGNAME],
            hdr[rpm.RPMTAG_CHANGELOGTEXT]),
        'distribution': cvt(hdr[rpm.RPMTAG_DISTRIBUTION]),
        'vendor': cvt(hdr[rpm.RPMTAG_VENDOR]),
        'gif': cvt(hdr[rpm.RPMTAG_GIF], bytes),
        'xpm': cvt(hdr[rpm.RPMTAG_XPM], bytes),
        'license': cvt(hdr[rpm.RPMTAG_LICENSE]),
        'group_': cvt(hdr[rpm.RPMTAG_GROUP]),
        'url': cvt(hdr[rpm.RPMTAG_URL]),
        'os': cvt(hdr[rpm.RPMTAG_OS]),
        'prein': cvt(hdr[rpm.RPMTAG_PREIN]),
        'postin': cvt(hdr[rpm.RPMTAG_POSTIN]),
        'preun': cvt(hdr[rpm.RPMTAG_PREUN]),
        'postun': cvt(hdr[rpm.RPMTAG_POSTUN]),
        'icon': cvt(hdr[rpm.RPMTAG_ICON], bytes),
        'preinprog': cvt(hdr[rpm.RPMTAG_PREINPROG]),
        'postinprog': cvt(hdr[rpm.RPMTAG_POSTINPROG]),
        'preunprog': cvt(hdr[rpm.RPMTAG_PREUNPROG]),
        'postunprog': cvt(hdr[rpm.RPMTAG_POSTUNPROG]),
        'buildarchs': cvt(hdr[rpm.RPMTAG_BUILDARCHS]),
        'verifyscript': cvt(hdr[rpm.RPMTAG_VERIFYSCRIPT]),
        'verifyscriptprog': cvt(hdr[rpm.RPMTAG_VERIFYSCRIPTPROG]),
        'prefixes': cvt(hdr[rpm.RPMTAG_PREFIXES]),
        'instprefixes': cvt(hdr[rpm.RPMTAG_INSTPREFIXES]),
        'optflags': cvt(hdr[rpm.RPMTAG_OPTFLAGS]),
        'disturl': cvt(hdr[rpm.RPMTAG_DISTURL]),
        'payloadformat': cvt(hdr[rpm.RPMTAG_PAYLOADFORMAT]),
        'payloadcompressor': cvt(hdr[rpm.RPMTAG_PAYLOADCOMPRESSOR]),
        'payloadflags': cvt(hdr[rpm.RPMTAG_PAYLOADFLAGS]),
        'platform': cvt(hdr[rpm.RPMTAG_PLATFORM]),
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
