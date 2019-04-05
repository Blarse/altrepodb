import argparse
import os
import datetime
import rpm
import psycopg2
import mapper

from utils import changelog_to_text, cvt, cvt_ts


def insert_package(conn, hdr):
    map_package = mapper.get_package_map(hdr)
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

        map_files = mapper.get_file_map(hdr)
        insert_list(cur, map_files, package_id, 'File')

        map_require = mapper.get_require_map(hdr)
        insert_list(cur, map_require, package_id, 'Require')

        map_conflict = mapper.get_conflict_map(hdr)
        insert_list(cur, map_conflict, package_id, 'Conflict')

        map_obsolete = mapper.get_obsolete_map(hdr)
        insert_list(cur, map_obsolete, package_id, 'Obsolete')

        map_provide = mapper.get_provide_map(hdr)
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
        try:
            header = get_header(ts, package)
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
