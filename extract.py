import argparse
import os
import rpm
import psycopg2
import datetime

from utils import changelog_to_text, cvt, cvt_ts


def insert_package(conn, hdr):
    map_package = {
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
        ', '.join(map_package.keys()),
        ', '.join(['%s'] * len(map_package))
    )
    cur = conn.cursor()
    cur.execute(sql, tuple(map_package.values()))
    package_id = cur.fetchone()
    if package_id:
        package_id = package_id[0]
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
        insert_list(cur, map_files, package_id, 'File')

        map_require = {
            'name': cvt(hdr[rpm.RPMTAG_REQUIRENAME]),
            'version': cvt(hdr[rpm.RPMTAG_REQUIREVERSION]),
            'flag': hdr[rpm.RPMTAG_REQUIREFLAGS],
        }
        insert_list(cur, map_require, package_id, 'Require')

        map_conflict = {
            'name': cvt(hdr[rpm.RPMTAG_CONFLICTNAME]),
            'version': cvt(hdr[rpm.RPMTAG_CONFLICTVERSION]),
            'flag': hdr[rpm.RPMTAG_CONFLICTFLAGS],
        }
        insert_list(cur, map_conflict, package_id, 'Conflict')

        map_obsolete = {
            'name': cvt(hdr[rpm.RPMTAG_OBSOLETENAME]),
            'version': cvt(hdr[rpm.RPMTAG_OBSOLETEVERSION]),
            'flag': hdr[rpm.RPMTAG_OBSOLETEFLAGS],
        }
        insert_list(cur, map_obsolete, package_id, 'Obsolete')

        map_provide = {
            'name': cvt(hdr[rpm.RPMTAG_PROVIDENAME]),
            'version': cvt(hdr[rpm.RPMTAG_PROVIDEVERSION]),
            'flag': hdr[rpm.RPMTAG_PROVIDEFLAGS],
        }
        insert_list(cur, map_provide, package_id, 'Provide')

    conn.commit()


def insert_list(cursor, tagmap, package_id, table_name):
    sql = 'INSERT INTO {0} (package_id, {1}) VALUES (%s, {2})'
    sql = sql.format(
        table_name,
        ', '.join(tagmap.keys()),
        ', '.join(['%s'] * len(tagmap))
    )
    for r in zip(*tagmap.values()):
        cursor.execute(sql, (package_id,) + r)


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
    err_cnt = 0
    package_cnt = 0
    for package in packages:
        print('Package: {0}'.format(package))
        header = get_header(ts, package)
        try:
            insert_package(conn, header)
        except (Exception, psycopg2.DatabaseError) as error:
            print(error)
            if err_cnt > 50:
                print('Error limit reached')
                break
            else:
                err_cnt += 1
                continue
        except KeyboardInterrupt:
            print('User stopped program')
            break
        else:
            package_cnt += 1
            print('Package successful loaded')

    if conn is not None:
        conn.close()

    return package_cnt


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='Path to packages')
    parser.add_argument('-d', type=str, help='Database name', default='repodb')
    parser.add_argument('-u', type=str, help='Database username', default='underwit')
    parser.add_argument('-v', action='count', help='Database username', default=0)
    return parser.parse_args()


def main():
    args = get_args()
    print('{0} - Start loading packages'.format(datetime.datetime.now()))
    pc = load(args)
    print('{0} - Stop loading packages'.format(datetime.datetime.now()))
    print('{0} packages loaded'.format(pc))


if __name__ == '__main__':
    main()
