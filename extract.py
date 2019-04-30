import argparse
import os
import datetime
import rpm
import psycopg2
import mapper

from psycopg2 import extras
from utils import cvt, packager_parse, get_logger, timing


log = get_logger('extract')

@timing
def check_package(conn, hdr):
    """Check whether the package is in the database.

    return sha1 hash of package from database or None
    """
    sql = "SELECT sha1header FROM Package WHERE sha1header='{0}'"
    with conn.cursor() as cur:
        cur.execute(sql.format(cvt(hdr[rpm.RPMDBI_SHA1HEADER])))
        sha1header = cur.fetchone()
        if sha1header:
            return sha1header[0]
        return None


@timing
def insert_package(conn, hdr, package_filename):
    """Insert information about package into database.

    Also:
    insert packager, files, requires, provides, confilcts, obsolets
    """
    map_package = mapper.get_package_map(hdr)
    map_package.update(filename=os.path.basename(package_filename))
    name_email = packager_parse(cvt(hdr[rpm.RPMTAG_PACKAGER]))
    if name_email is not None:
        pid = check_packager(conn, *name_email)
        if pid is None:
            pid = insert_packager(conn, *name_email)
        if pid is not None:
            map_package.update(packager_id=pid)

    sql_insert = (
            'INSERT INTO Package ({0}) VALUES ({1})'
            ' ON CONFLICT DO NOTHING RETURNING sha1header'
        ).format(
            ', '.join(map_package.keys()),
            ', '.join(['%s'] * len(map_package))
        )
    with conn.cursor() as cur:
        cur.execute(sql_insert, tuple(map_package.values()))
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
    return package_sha1


@timing
def insert_list(cursor, tagmap, package_sha1, table_name):
    """Insert list as batch."""
    sql = 'INSERT INTO {0} (package_sha1, {1}) VALUES (%s, {2})'
    sql = sql.format(
        table_name,
        ', '.join(tagmap.keys()),
        ', '.join(['%s'] * len(tagmap))
    )
    r = [(package_sha1,) + i for i in zip(*tagmap.values())]
    extras.execute_batch(cursor, sql, r)


@timing
def insert_assigment_name(conn, assigment_name, assigment_tag=None):
    with conn.cursor() as cur:
        sql = (
            'INSERT INTO AssigmentName (name, datetime_release, tag) '
            'VALUES (%s, %s, %s) RETURNING id'
        )
        cur.execute(sql, (assigment_name, datetime.datetime.now(), assigment_tag))
        an_id = cur.fetchone()
        if an_id:
            conn.commit()
            return an_id[0]


@timing
def check_assigment(conn, assigmentname_id, sha1header):
    """Check whether the assigment is in the database.

    return id or None
    """
    sql = (
        "SELECT id FROM Assigment WHERE assigmentname_id={0}"
        " AND package_sha1='{1}'"
    ).format(assigmentname_id, sha1header)
    with conn.cursor() as cur:
        cur.execute(sql)
        as_id = cur.fetchone()
        if as_id:
            return as_id[0]


@timing
def insert_assigment(conn, assigmentname_id, sha1header):
    sql = (
        'INSERT INTO Assigment (assigmentname_id, package_sha1)'
        ' VALUES (%s, %s) RETURNING id'
    )
    with conn.cursor() as cur:
        cur.execute(sql, (assigmentname_id, sha1header))
        as_id = cur.fetchone()
        if as_id:
            conn.commit()
            return as_id[0]


@timing
def check_packager(conn, name, email):
    """Check whether the packager is in the database.

    return id or None
    """
    sql = "SELECT id FROM Packager WHERE name='{0}' AND email='{1}'"
    with conn.cursor() as cur:
        cur.execute(sql.format(name, email))
        p_id = cur.fetchone()
        if p_id:
            return p_id[0]


@timing
def insert_packager(conn, name, email):
    sql = 'INSERT INTO Packager (name, email) VALUES (%s, %s) RETURNING id'
    with conn.cursor() as cur:
        cur.execute(sql, (name, email))
        p_id = cur.fetchone()
        if p_id:
            conn.commit()
            return p_id[0]


@timing
def find_packages(path):
    """Recursively walk through directory for find rpm packages.

    return generator
    """
    for dirname, _, filenames in os.walk(path):
        for filename in filenames:
            f = os.path.join(dirname, filename)
            if f.endswith('.rpm') and not os.path.islink(f):
                yield f


@timing
def get_header(ts, rpmfile):
    f = os.open(rpmfile, os.O_RDONLY)
    h = ts.hdrFromFdno(f)
    os.close(f)
    return h


@timing
def get_conn_str(args):
    r = []
    if args.dbname is not None:
        r.append("dbname={0}".format(args.dbname))
    if args.user is not None:
        r.append("user={0}".format(args.user))
    if args.password is not None:
        r.append("password={0}".format(args.password))
    if args.host is not None:
        r.append("host={0}".format(args.host))
    if args.port is not None:
        r.append("port={0}".format(args.port))
    return ' '.join(r)


@timing
def load(args):
    ts = rpm.TransactionSet()
    packages = find_packages(args.path)
    conn = psycopg2.connect(get_conn_str(args))
    aname_id = insert_assigment_name(conn, args.assigment, args.tag)
    if aname_id is None:
        raise RuntimeError('Unexpected behavior')
    for package in packages:
        log.debug('Processing: {0}'.format(package))
        try:
            header = get_header(ts, package)
            sha1header = check_package(conn, header)
            if sha1header is None:
                sha1header = insert_package(conn, header, package)
            if sha1header is None:
                raise RuntimeError('Unexpected behavior')
            if check_assigment(conn, aname_id, sha1header) is None:
                insert_assigment(conn, aname_id, sha1header)
        except psycopg2.DatabaseError as error:
            log.error(error)

    if conn is not None:
        conn.close()


@timing
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('assigment', type=str, help='Assigment name')
    parser.add_argument('path', type=str, help='Path to packages')
    parser.add_argument('-t', '--tag', type=str, help='Assigment tag')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database password')
    parser.add_argument('-u', '--user', type=str, help='Database login')
    parser.add_argument('-P', '--password', type=str, help='Database password')
    return parser.parse_args()

@timing
def main():
    args = get_args()
    log.info('Start loading packages')
    try:
        load(args)
    except Exception as error:
        log.error(error)
    finally:
        log.info('Stop loading packages')


if __name__ == '__main__':
    main()
