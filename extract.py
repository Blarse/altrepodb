import argparse
import os
import datetime
import rpm
import psycopg2
import mapper

from psycopg2 import extras
from utils import cvt


def insert_package(conn, hdr, package_filename):
    map_package = mapper.get_package_map(hdr)
    map_package.update(filename=os.path.basename(package_filename))
    sql = (
            'INSERT INTO Package ({0}) VALUES ({1})'
            ' ON CONFLICT DO NOTHING RETURNING sha1header'
        )
    sql = sql.format(
        ', '.join(map_package.keys()),
        ', '.join(['%s'] * len(map_package))
    )
    with conn.cursor() as cur:
        cur.execute(sql, tuple(map_package.values()))
        package_sha1 = cur.fetchone()
        if package_sha1:
            package_sha1 = package_sha1[0]

            map_files = mapper.get_file_map(hdr)
            insert_list(cur, map_files, package_sha1, 'File')

            map_require = mapper.get_require_map(hdr)
            insert_list(cur, map_require, package_sha1, 'Require')

            map_conflict = mapper.get_conflict_map(hdr)
            insert_list(cur, map_conflict, package_sha1, 'Conflict')

            map_obsolete = mapper.get_obsolete_map(hdr)
            insert_list(cur, map_obsolete, package_sha1, 'Obsolete')

            map_provide = mapper.get_provide_map(hdr)
            insert_list(cur, map_provide, package_sha1, 'Provide')
    conn.commit()


def insert_list(cursor, tagmap, package_sha1, table_name):
    sql = 'INSERT INTO {0} (package_sha1, {1}) VALUES (%s, {2})'
    sql = sql.format(
        table_name,
        ', '.join(tagmap.keys()),
        ', '.join(['%s'] * len(tagmap))
    )
    r = [(package_sha1,) + i for i in zip(*tagmap.values())]
    extras.execute_batch(cursor, sql, r)


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


def get_already(conn):
    with conn.cursor() as cur:
        cur.execute('SELECT sha1header FROM Package')
        return set(i[0] for i in cur.fetchall())


def load(args):
    ts = rpm.TransactionSet()
    packages = find_packages(args.path)
    conn = psycopg2.connect('dbname={0} user={1}'.format(args.d, args.u))
    already = get_already(conn)
    package_cnt = 0
    for package in packages:
        try:
            header = get_header(ts, package)
            if cvt(header[rpm.RPMDBI_SHA1HEADER]) in already:
                continue
            insert_package(conn, header, package)
        except (Exception, psycopg2.DatabaseError) as error:
            print(error)
        except KeyboardInterrupt:
            print('User stopped program')
            break
        else:
            package_cnt += 1

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
