import rpm

from utils import changelog_to_text, cvt, cvt_ts


def detect_arch(hdr):
    package_name = cvt(hdr[rpm.RPMTAG_NAME])
    if package_name.startswith('i586-'):
        return 'x86_64-i586'

    return cvt(hdr[rpm.RPMTAG_ARCH])


def get_package_map(hdr):
    map_package = {
        'sha1header': cvt(hdr[rpm.RPMDBI_SHA1HEADER]),
        'name': cvt(hdr[rpm.RPMTAG_NAME]),
        'arch': detect_arch(hdr),
        'version': cvt(hdr[rpm.RPMTAG_VERSION]),
        'release': cvt(hdr[rpm.RPMTAG_RELEASE]),
        'epoch': rpm.RPMTAG_EPOCH,
        'serial_': rpm.RPMTAG_SERIAL,
        'summary': cvt(hdr[rpm.RPMTAG_SUMMARY]),
        'description': cvt(hdr[rpm.RPMTAG_DESCRIPTION]),
        'changelog': changelog_to_text(
            hdr[rpm.RPMTAG_CHANGELOGTIME],
            hdr[rpm.RPMTAG_CHANGELOGNAME],
            hdr[rpm.RPMTAG_CHANGELOGTEXT]),
        'buildtime': hdr[rpm.RPMTAG_BUILDTIME],
        'buildhost': cvt(hdr[rpm.RPMTAG_BUILDHOST]),
        'size': hdr[rpm.RPMTAG_SIZE],
        'distribution': cvt(hdr[rpm.RPMTAG_DISTRIBUTION]),
        'vendor': cvt(hdr[rpm.RPMTAG_VENDOR]),
        'gif': hdr[rpm.RPMTAG_GIF],
        'xpm': hdr[rpm.RPMTAG_XPM],
        'license': cvt(hdr[rpm.RPMTAG_LICENSE]),
        'group_': cvt(hdr[rpm.RPMTAG_GROUP]),
        'source': cvt(hdr[rpm.RPMTAG_SOURCE]),
        'patch': cvt(hdr[rpm.RPMTAG_PATCH]),
        'url': cvt(hdr[rpm.RPMTAG_URL]),
        'os': cvt(hdr[rpm.RPMTAG_OS]),
        'prein': cvt(hdr[rpm.RPMTAG_PREIN]),
        'postin': cvt(hdr[rpm.RPMTAG_POSTIN]),
        'preun': cvt(hdr[rpm.RPMTAG_PREUN]),
        'postun': cvt(hdr[rpm.RPMTAG_POSTUN]),
        'icon': hdr[rpm.RPMTAG_ICON],
        'archivesize': rpm.RPMTAG_ARCHIVESIZE,
        'rpmversion': cvt(hdr[rpm.RPMTAG_RPMVERSION]),
        'preinprog': cvt(hdr[rpm.RPMTAG_PREINPROG]),
        'postinprog': cvt(hdr[rpm.RPMTAG_POSTINPROG]),
        'preunprog': cvt(hdr[rpm.RPMTAG_PREUNPROG]),
        'postunprog': cvt(hdr[rpm.RPMTAG_POSTUNPROG]),
        'buildarchs': cvt(hdr[rpm.RPMTAG_BUILDARCHS]),
        'verifyscript': cvt(hdr[rpm.RPMTAG_VERIFYSCRIPT]),
        'verifyscriptprog': cvt(hdr[rpm.RPMTAG_VERIFYSCRIPTPROG]),
        'cookie': cvt(hdr[rpm.RPMTAG_COOKIE]),
        'prefixes': cvt(hdr[rpm.RPMTAG_PREFIXES]),
        'instprefixes': cvt(hdr[rpm.RPMTAG_INSTPREFIXES]),
        'sourcepackage': bool(hdr[rpm.RPMTAG_SOURCEPACKAGE]),
        'optflags': cvt(hdr[rpm.RPMTAG_OPTFLAGS]),
        'disturl': cvt(hdr[rpm.RPMTAG_DISTURL]),
        'payloadformat': cvt(hdr[rpm.RPMTAG_PAYLOADFORMAT]),
        'payloadcompressor': cvt(hdr[rpm.RPMTAG_PAYLOADCOMPRESSOR]),
        'payloadflags': cvt(hdr[rpm.RPMTAG_PAYLOADFLAGS]),
        'platform': cvt(hdr[rpm.RPMTAG_PLATFORM]),
        'disttag': cvt(hdr[rpm.RPMTAG_DISTTAG]),
        'sourcerpm': cvt(hdr[rpm.RPMTAG_SOURCERPM]),
    }
    return map_package


def get_file_map(hdr):
    map_files = {
        'filename': cvt(hdr[rpm.RPMTAG_FILENAMES]),
        'filesize': cvt(hdr[rpm.RPMTAG_FILESIZES]),
        'filemode': cvt(hdr[rpm.RPMTAG_FILEMODES]),
        'filerdev': cvt(hdr[rpm.RPMTAG_FILERDEVS]),
        'filemtime': cvt_ts(hdr[rpm.RPMTAG_FILEMTIMES]),
        'filemd5': cvt(hdr[rpm.RPMTAG_FILEMD5S]),
        'filelinkto': cvt(hdr[rpm.RPMTAG_FILELINKTOS]),
        'fileflag': cvt(hdr[rpm.RPMTAG_FILEFLAGS]),
        'fileusername': cvt(hdr[rpm.RPMTAG_FILEUSERNAME]),
        'filegroupname': cvt(hdr[rpm.RPMTAG_FILEGROUPNAME]),
        'fileverifyflag': cvt(hdr[rpm.RPMTAG_FILEVERIFYFLAGS]),
        'filedevice': cvt(hdr[rpm.RPMTAG_FILEDEVICES]),
        'fileinode': cvt(hdr[rpm.RPMTAG_FILEINODES]),
        'filelang': cvt(hdr[rpm.RPMTAG_FILELANGS]),
        'fileclass': cvt(hdr[rpm.RPMTAG_FILECLASS]),
        'dirindex': cvt(hdr[rpm.RPMTAG_DIRINDEXES]),
        'basename': cvt(hdr[rpm.RPMTAG_BASENAMES]),
    }
    return map_files


def get_require_map(hdr):
    map_require = {
        'name': cvt(hdr[rpm.RPMTAG_REQUIRENAME]),
        'version': cvt(hdr[rpm.RPMTAG_REQUIREVERSION]),
        'flag': hdr[rpm.RPMTAG_REQUIREFLAGS],
    }
    return map_require


def get_conflict_map(hdr):
    map_conflict = {
        'name': cvt(hdr[rpm.RPMTAG_CONFLICTNAME]),
        'version': cvt(hdr[rpm.RPMTAG_CONFLICTVERSION]),
        'flag': hdr[rpm.RPMTAG_CONFLICTFLAGS],
    }
    return map_conflict


def get_obsolete_map(hdr):
    map_obsolete = {
        'name': cvt(hdr[rpm.RPMTAG_OBSOLETENAME]),
        'version': cvt(hdr[rpm.RPMTAG_OBSOLETEVERSION]),
        'flag': hdr[rpm.RPMTAG_OBSOLETEFLAGS],
    }
    return map_obsolete


def get_provide_map(hdr):
    map_provide = {
        'name': cvt(hdr[rpm.RPMTAG_PROVIDENAME]),
        'version': cvt(hdr[rpm.RPMTAG_PROVIDEVERSION]),
        'flag': hdr[rpm.RPMTAG_PROVIDEFLAGS],
    }
    return map_provide
