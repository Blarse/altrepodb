import argparse
import os
import rpm
import psycopg2

from utils import changelog_to_text, cvt


def insert_package(conn, hdr):
    tagsmap = {
        'sha1header': cvt(hdr[rpm.RPMDBI_SHA1HEADER]),
        'name': cvt(hdr[rpm.RPMTAG_NAME]),
        'arch': cvt(hdr[rpm.RPMTAG_ARCH]),
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
        'sourcepackage': bool(rpm.RPMTAG_SOURCEPACKAGE),
        'optflags': cvt(hdr[rpm.RPMTAG_OPTFLAGS]),
        'disturl': cvt(hdr[rpm.RPMTAG_DISTURL]),
        'payloadformat': cvt(hdr[rpm.RPMTAG_PAYLOADFORMAT]),
        'payloadcompressor': cvt(hdr[rpm.RPMTAG_PAYLOADCOMPRESSOR]),
        'payloadflags': cvt(hdr[rpm.RPMTAG_PAYLOADFLAGS]),
        'platform': cvt(hdr[rpm.RPMTAG_PLATFORM]),
        'sourcepkgid': hdr[rpm.RPMTAG_SOURCEPKGID],
        'disttag': cvt(hdr[rpm.RPMTAG_DISTTAG]),
    }

    sql = (
            'INSERT INTO Package ({0}) VALUES ({1})'
            ' ON CONFLICT DO NOTHING RETURNING id'
        )
    sql = sql.format(
        ', '.join(tagsmap.keys()),
        ', '.join(['%s'] * len(tagsmap))
    )
    cur = conn.cursor()
    cur.execute(sql, tuple(tagsmap.values()))
    package_id = cur.fetchone()
    if package_id:
        print(package_id)
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


def load(args):
    ts = rpm.TransactionSet()
    packages = find_packages(args.path)
    conn = psycopg2.connect('dbname={0} user={1}'.format(args.d, args.u))
    for i, package in enumerate(packages):
        if args.v > 0:
            print('Loading package: {0}'.format(package))
        header = get_header(ts, package)
        insert_package(conn, header)
        if i > args.l:
            if args.v > 0:
                print('Limit is reach')
            break
    conn.close()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='Path to packages')
    parser.add_argument('-d', type=str, help='Database name', default='repodb')
    parser.add_argument('-u', type=str, help='Database username', default='underwit')
    parser.add_argument('-v', action='count', help='Database username', default=0)
    parser.add_argument('-l', type=int, help='Load limit (for debug)', default=10)
    return parser.parse_args()


def main():
    args = get_args()
    load(args)


if __name__ == '__main__':
    main()
