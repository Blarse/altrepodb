import os
import rpm
import psycopg2

from utils import changelog_to_text, cvt

# map_db2tag = {
#     "name": rpm.RPMTAG_NAME,
#     "arch": rpm.RPMTAG_ARCH,
#     "version": rpm.RPMTAG_VERSION,
#     "release": rpm.RPMTAG_RELEASE,
#     "epoch": rpm.RPMTAG_EPOCH,
#     "serial_": rpm.RPMTAG_SERIAL,
#     "summary": rpm.RPMTAG_SUMMARY,
#     "description": rpm.RPMTAG_DESCRIPTION,
#     "buildtime": rpm.RPMTAG_BUILDTIME,
#     "buildhost": rpm.RPMTAG_BUILDHOST,
#     "size": rpm.RPMTAG_SIZE,
#     "distribution": rpm.RPMTAG_DISTRIBUTION,
#     "vendor": rpm.RPMTAG_VENDOR,
#     "gif": rpm.RPMTAG_GIF,
#     "xpm": rpm.RPMTAG_XPM,
#     "license": rpm.RPMTAG_LICENSE,
#     "group_": rpm.RPMTAG_GROUP,
#     "source": rpm.RPMTAG_SOURCE,
#     "patch": rpm.RPMTAG_PATCH,
#     "url": rpm.RPMTAG_URL,
#     "os": rpm.RPMTAG_OS,
#     "prein": rpm.RPMTAG_PREIN,
#     "postin": rpm.RPMTAG_POSTIN,
#     "preun": rpm.RPMTAG_PREUN,
#     "postun": rpm.RPMTAG_POSTUN,
#     "icon": rpm.RPMTAG_ICON,
#     "archivesize": rpm.RPMTAG_ARCHIVESIZE,
#     "rpmversion": rpm.RPMTAG_RPMVERSION,
#     "preinprog": rpm.RPMTAG_PREINPROG,
#     "postinprog": rpm.RPMTAG_POSTINPROG,
#     "preunprog": rpm.RPMTAG_PREUNPROG,
#     "postunprog": rpm.RPMTAG_POSTUNPROG,
#     "buildarchs": rpm.RPMTAG_BUILDARCHS,
#     "verifyscript": rpm.RPMTAG_VERIFYSCRIPT,
#     "verifyscriptprog": rpm.RPMTAG_VERIFYSCRIPTPROG,
#     "cookie": rpm.RPMTAG_COOKIE,
#     "prefixes": rpm.RPMTAG_PREFIXES,
#     "instprefixes": rpm.RPMTAG_INSTPREFIXES,
#     "sourcepackage": rpm.RPMTAG_SOURCEPACKAGE,
#     "optflags": rpm.RPMTAG_OPTFLAGS,
#     "disturl": rpm.RPMTAG_DISTURL,
#     "payloadformat": rpm.RPMTAG_PAYLOADFORMAT,
#     "payloadcompressor": rpm.RPMTAG_PAYLOADCOMPRESSOR,
#     "payloadflags": rpm.RPMTAG_PAYLOADFLAGS,
#     "platform": rpm.RPMTAG_PLATFORM,
#     "sourcepkgid": rpm.RPMTAG_SOURCEPKGID,
#     "disttag":rpm.RPMTAG_DISTTAG,
# }


def insert_package(conn, hdr):
    tagsmap = {
        "name": cvt(hdr[rpm.RPMTAG_NAME]),
        "arch": cvt(hdr[rpm.RPMTAG_ARCH]),
        "version": cvt(hdr[rpm.RPMTAG_VERSION]),
        "release": cvt(hdr[rpm.RPMTAG_RELEASE]),
        "epoch": rpm.RPMTAG_EPOCH,
        "serial_": rpm.RPMTAG_SERIAL,
        "summary": cvt(hdr[rpm.RPMTAG_SUMMARY]),
        "description": cvt(hdr[rpm.RPMTAG_DESCRIPTION]),
        "changelog": changelog_to_text(
            hdr[rpm.RPMTAG_CHANGELOGTIME],
            hdr[rpm.RPMTAG_CHANGELOGNAME],
            hdr[rpm.RPMTAG_CHANGELOGTEXT]),
        "buildtime": hdr[rpm.RPMTAG_BUILDTIME],
        "buildhost": cvt(hdr[rpm.RPMTAG_BUILDHOST]),
        "size": hdr[rpm.RPMTAG_SIZE],
        "distribution": cvt(hdr[rpm.RPMTAG_DISTRIBUTION]),
        "vendor": cvt(hdr[rpm.RPMTAG_VENDOR]),
        "gif": hdr[rpm.RPMTAG_GIF],
        "xpm": hdr[rpm.RPMTAG_XPM],
        "license": cvt(hdr[rpm.RPMTAG_LICENSE]),
        "group_": cvt(hdr[rpm.RPMTAG_GROUP]),
        "source": cvt(hdr[rpm.RPMTAG_SOURCE]),
        "patch": cvt(hdr[rpm.RPMTAG_PATCH]),
        "url": cvt(hdr[rpm.RPMTAG_URL]),
        "os": cvt(hdr[rpm.RPMTAG_OS]),
        "prein": cvt(hdr[rpm.RPMTAG_PREIN]),
        "postin": cvt(hdr[rpm.RPMTAG_POSTIN]),
        "preun": cvt(hdr[rpm.RPMTAG_PREUN]),
        "postun": cvt(hdr[rpm.RPMTAG_POSTUN]),
        "icon": hdr[rpm.RPMTAG_ICON],
        "archivesize": rpm.RPMTAG_ARCHIVESIZE,
        "rpmversion": cvt(hdr[rpm.RPMTAG_RPMVERSION]),
        "preinprog": cvt(hdr[rpm.RPMTAG_PREINPROG]),
        "postinprog": cvt(hdr[rpm.RPMTAG_POSTINPROG]),
        "preunprog": cvt(hdr[rpm.RPMTAG_PREUNPROG]),
        "postunprog": cvt(hdr[rpm.RPMTAG_POSTUNPROG]),
        "buildarchs": cvt(hdr[rpm.RPMTAG_BUILDARCHS]),
        "verifyscript": cvt(hdr[rpm.RPMTAG_VERIFYSCRIPT]),
        "verifyscriptprog": cvt(hdr[rpm.RPMTAG_VERIFYSCRIPTPROG]),
        "cookie": cvt(hdr[rpm.RPMTAG_COOKIE]),
        "prefixes": cvt(hdr[rpm.RPMTAG_PREFIXES]),
        "instprefixes": cvt(hdr[rpm.RPMTAG_INSTPREFIXES]),
        "sourcepackage": bool(rpm.RPMTAG_SOURCEPACKAGE),
        "optflags": cvt(hdr[rpm.RPMTAG_OPTFLAGS]),
        "disturl": cvt(hdr[rpm.RPMTAG_DISTURL]),
        "payloadformat": cvt(hdr[rpm.RPMTAG_PAYLOADFORMAT]),
        "payloadcompressor": cvt(hdr[rpm.RPMTAG_PAYLOADCOMPRESSOR]),
        "payloadflags": cvt(hdr[rpm.RPMTAG_PAYLOADFLAGS]),
        "platform": cvt(hdr[rpm.RPMTAG_PLATFORM]),
        "sourcepkgid": hdr[rpm.RPMTAG_SOURCEPKGID],
        "disttag": cvt(hdr[rpm.RPMTAG_DISTTAG])
    }

    sql = "INSERT INTO Package ({0}) VALUES ({1})"
    sql = sql.format(", ".join(tagsmap.keys()), ", ".join(["%s"] * len(tagsmap)))
    cur = conn.cursor()
    cur.execute(sql, tuple(tagsmap.values()))
    conn.commit()



def find_packages(path):
    for dirname, _, filenames in os.walk(path):
        for filename in filenames:
            f = os.path.join(dirname, filename)
            if f.endswith('.rpm') and not os.path.islink(f):
                yield f


def get_header(ts, rpmfile):
    f = os.open(rpmfile, os.O_RDONLY)
    h = ts.hdrFromFdno(f)
    os.close(f)
    return h


def load():
    ts = rpm.TransactionSet()
    conn = psycopg2.connect("dbname=repodb user=underwit")
    packages = find_packages('/mnt/repo/Sisyphus/files/')
    for i, package in enumerate(packages):
        header = get_header(ts, package)
        insert_package(conn, header)
        if i == 100:
            break
    conn.close()


def main():
    load()


if __name__ == '__main__':
    main()
