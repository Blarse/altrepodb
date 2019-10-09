import argparse
import pycdlib
import os
import os.path
import rpm
import tempfile
import hashlib
import logging
import utils
import extract
from io import BytesIO
from uuid import uuid4
from collections import defaultdict
from PySquashfsImage import SquashFsImage
from functools import reduce


log = logging.getLogger('extract')


def process_iso(conn, iso, args, constraint_name):
    make_temporary_table(conn)
    for sqfs in ['/altinst', '/live', '/rescue']:
        tmp_file = tempfile.NamedTemporaryFile()
        try:
            iso.get_file_from_iso_fp(tmp_file, rr_path=sqfs)
        except pycdlib.pycdlibexception.PyCdlibInvalidInput as e:
            log.info('not found {0} SquashFS'.format(sqfs))
            continue
        tmp_file.seek(0)
        m = hashlib.sha1()
        m.update(tmp_file.read())
        squash_sha1 = m.hexdigest()
        log.info('iso processing sqfs: {}, sha1: {}'.format(sqfs, squash_sha1))
        path_md5 = process_squashfs(tmp_file.name, squash_sha1) # {(filename, filemd5): {'data': ...}}
        # store (filename, filemd5) from squashfs to temporary table PathMd5Temp
        path_md5_ttt(conn, path_md5)
        # store (pkghash, name, buildtime) to temporary table PkgTemp for packages whose file are in PathMd5Temp
        get_package(conn, constraint_name)
        # store (pkghash, filename, filemd5) to temporary tabke FileTemp for packages from PkgTemp table
        get_file(conn)
        assigments = make_assigments(conn)
        aname_id = str(uuid4())
        extract.insert_assigment_name(
            conn,
            assigment_name=args.assigment + sqfs,
            uuid=aname_id,
            tag=args.tag,
            assigment_date=args.date,
            complete=1
        )
        name = '{0}-not-found-files-{1}'.format(sqfs.replace('/', ''), args.assigment)
        orphan_pkghash = make_orphan_package(conn, name, squash_sha1)
        assigments.add(orphan_pkghash)
        write_orphan_files(conn, path_md5)
        extract.insert_assigment(conn, aname_id, assigments)
        log.info('iso saved: {}, assigments'.format(len(assigments)))
        tmp_file.close()


def make_orphan_package(conn, name, sha1):
    pkghash = utils.mmhash(sha1)
    conn.execute(
        'INSERT INTO Package_buffer (pkghash, name) VALUES',
        [{'pkghash': pkghash, 'name': name}]
    )
    return pkghash


def write_orphan_files(conn, path_md5):
    orphan_files = conn.execute(
        'SELECT filename, filemd5 FROM PathMd5Temp WHERE (filename, filemd5)'
        ' NOT IN (SELECT filename, filemd5 FROM FileTemp)'
    )
    log.info('found {} orphan files'.format(len(orphan_files)))
    conn.execute(
        'INSERT INTO File_buffer (filename, filelinkto, filemd5, pkghash, '
        'filesize, filemode, filemtime, fileusername, filegroupname, '
        'fileverifyflag, fileclass) VALUES', 
        [path_md5[k] for k in orphan_files]
    )


def make_assigments(conn):
    sql = (
        'SELECT argMax(pkghash, buildtime) FROM '
        '(SELECT pkghash, COUNT(*) / any(xf.c) kf FROM FileTemp '
        'LEFT JOIN (SELECT pkghash, COUNT(filename) as c FROM FileTemp '
        'GROUP BY pkghash) AS xf USING pkghash WHERE (filename, filemd5) '
        'IN (SELECT filename, filemd5 FROM PathMd5Temp) GROUP BY pkghash) '
        'LEFT JOIN PkgTemp USING pkghash WHERE kf=1 GROUP BY name'
    )
    result = conn.execute(sql)
    return {i[0] for i in result}


def process_squashfs(filename, squash_sha1):
    image = SquashFsImage(filename)
    path_md5 = defaultdict(dict)
    for f in image.root.findAll():
        if f.isFolder():
            continue
        h_ = '' # '\0' * 32
        l_ = ''
        c_ = ''
        if f.isLink():
            l_ = f.getLink()
            c_ = 'symbolic link to `{0}\''.format(f.getLink())
        else:
            m = hashlib.md5()
            try:
                m.update(f.getContent())
            except Exception as e:
                log.error('error: {}, file: {}'.format(e, f.getPath()))
            else:
                h_ = m.hexdigest()
        data = {}
        data['filename'] = f.getPath()
        data['filelinkto'] = l_
        data['filemd5'] = h_
        data['pkghash'] = utils.mmhash(squash_sha1)
        data['filesize'] = f.getLength()
        data['filemode'] = f.inode.mode
        data['filemtime'] = utils.cvt_ts(f.inode.time)
        data['fileusername'] = str(f.inode.uid)
        data['filegroupname'] = str(f.inode.gid)
        data['fileverifyflag'] = f.inode.xattr
        data['fileclass'] = c_
        path_md5[(f.getPath(), h_)].update(data)
    image.close()
    return path_md5


def make_temporary_table(conn):
    conn.execute(
        'CREATE TEMPORARY TABLE IF NOT EXISTS PkgTemp '
        '(pkghash UInt64, name String, buildtime UInt32)'
    )
    conn.execute(
        'CREATE TEMPORARY TABLE IF NOT EXISTS PathMd5Temp '
        '(filename String, filemd5 FixedString(32))'
    )
    conn.execute(
        'CREATE TEMPORARY TABLE IF NOT EXISTS FileTemp '
        '(pkghash UInt64, filename String, filemd5 FixedString(32))'
    )


def path_md5_ttt(conn, path_md5):
    """Put path md5 to temporary table
    """
    conn.execute('TRUNCATE TABLE IF EXISTS PathMd5Temp')
    conn.execute(
        'INSERT INTO PathMd5Temp (filename, filemd5) VALUES',
        [{'filename': filename, 'filemd5': filemd5} for filename, filemd5 in path_md5.keys()]
    )


def get_package(conn, constraint_name):
    conn.execute('TRUNCATE TABLE IF EXISTS PkgTemp')
    sql = (
        "INSERT INTO PkgTemp SELECT pkghash, name, buildtime FROM Package_buffer WHERE "
        "pkghash IN (SELECT pkghash FROM Assigment_buffer WHERE uuid IN "
        "(SELECT uuid FROM AssigmentName WHERE assigment_name IN %(constraint_name)s)) "
        "AND notLike(name, '%%not-found%%') AND sourcepackage=%(srcp)s "
        "AND pkghash IN (SELECT DISTINCT(pkghash) FROM File_buffer "
        "WHERE (filename, filemd5) IN (SELECT filename, filemd5 FROM PathMd5Temp))"
    )
    conn.execute(sql, {'srcp': 0, 'constraint_name': constraint_name})


def get_file(conn):
    conn.execute('TRUNCATE TABLE IF EXISTS FileTemp')
    sql = (
        "INSERT INTO FileTemp SELECT pkghash, filename, filemd5 FROM "
        "File_buffer WHERE fileclass != 'directory' AND pkghash IN "
        "(SELECT pkghash FROM PkgTemp)"
    )
    conn.execute(sql)
