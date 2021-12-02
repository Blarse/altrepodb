# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021 BaseALT Ltd
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <http://www.gnu.org/licenses/>.

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


os.environ['LANG'] = 'C'

log = logging.getLogger('extract')


def process_iso(conn, iso, args, constraint_name):
    make_temporary_table(conn)
    for sqfs in ['/altinst', '/live', '/rescue']:
        buf = BytesIO()
        try:
            iso.get_file_from_iso_fp(buf, rr_path=sqfs)
        except pycdlib.pycdlibexception.PyCdlibInvalidInput as e:
            log.info('not found {0} SquashFS'.format(sqfs))
            continue
        buf.seek(0)
        m = hashlib.sha1()
        m.update(buf.read())
        squash_sha1 = m.hexdigest()
        log.info('iso processing sqfs: {}, sha1: {}'.format(sqfs, squash_sha1))
        path_md5 = process_squashfs(buf, squash_sha1) # {(hashname, filemd5): {'data': ...}}
        # store (hashname, filemd5) from squashfs to temporary table PathMd5Temp
        path_md5_ttt(conn, path_md5)
        # store (pkghash, name, buildtime) to temporary table PkgTemp for packages whose file are in PathMd5Temp
        get_package(conn, constraint_name)
        # store (pkghash, hashname, filemd5) to temporary tabke FileTemp for packages from PkgTemp table
        get_file(conn)
        assignments = make_assignments(conn)
        aname_id = str(uuid4())
        extract.insert_assignment_name(
            conn,
            assignment_name=args.assignment + sqfs,
            uuid=aname_id,
            tag=args.tag,
            assignment_date=args.date,
            complete=1
        )
        name = '{0}-not-found-files-{1}'.format(sqfs.replace('/', ''), args.assignment)
        orphan_pkghash = make_orphan_package(conn, name, squash_sha1)
        assignments.add(orphan_pkghash)
        write_orphan_files(conn, path_md5)
        extract.insert_pkgset(conn, aname_id, assignments)
        log.info('iso saved: {}, assignments'.format(len(assignments)))


def make_orphan_package(conn, name, sha1):
    pkghash = utils.mmhash(sha1)
    conn.execute(
        'INSERT INTO Package_buffer (pkghash, pkgcs, name) VALUES',
        [{'pkghash': pkghash, 'pkgcs': sha1, 'name': name}]
    )
    return pkghash


def write_orphan_files(conn, path_md5):
    orphan_files = conn.execute("""SELECT hashname, filemd5
FROM PathMd5Temp
WHERE (hashname, filemd5)
          NOT IN (SELECT hashname, filemd5 FROM FileTemp)"""
                                )
    log.info('found {} orphan files'.format(len(orphan_files)))
    conn.execute("""INSERT INTO File_buffer (filename, filelinkto, filemd5, pkghash,
                         filesize, filemode, filemtime, fileusername,
                         filegroupname,
                         fileverifyflag, fileclass)
VALUES""",
                 [path_md5[k] for k in orphan_files]
                 )


def make_assignments(conn):
    sql = """SELECT argMax(pkghash, buildtime)
FROM (SELECT pkghash, COUNT(*) / any(xf.c) kf
      FROM FileTemp
               LEFT JOIN (SELECT pkghash, COUNT(hashname) as c
                          FROM FileTemp
                          GROUP BY pkghash) AS xf USING pkghash
      WHERE (hashname, filemd5)
                IN (SELECT hashname, filemd5 FROM PathMd5Temp)
      GROUP BY pkghash) AS kf
         LEFT JOIN PkgTemp USING pkghash
WHERE kf = 1
GROUP BY name"""

    result = conn.execute(sql)
    return {i[0] for i in result}


def process_squashfs(buf, squash_sha1):
    image = SquashFsImage()
    buf.seek(0)
    image.image_file = buf
    image.initialize(buf)
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
        data['hashname'] = utils.mmhash(f.getPath())
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
        path_md5[(utils.mmhash(f.getPath()), h_)].update(data)
    image.close()
    return path_md5


def make_temporary_table(conn):
    conn.execute(
        'CREATE TEMPORARY TABLE IF NOT EXISTS PkgTemp '
        '(pkghash UInt64, name String, buildtime UInt32)'
    )
    conn.execute("""CREATE TEMPORARY TABLE IF NOT EXISTS PathMd5Temp
(
    hashname UInt64,
    filemd5  FixedString(32)
)"""
                 )
    conn.execute("""CREATE TEMPORARY TABLE IF NOT EXISTS FileTemp
(
    pkghash  UInt64,
    hashname UInt64,
    filemd5  FixedString(32)
)"""
                 )


def path_md5_ttt(conn, path_md5):
    """Put path md5 to temporary table
    """
    conn.execute('TRUNCATE TABLE IF EXISTS PathMd5Temp')
    conn.execute(
        'INSERT INTO PathMd5Temp (hashname, filemd5) VALUES',
        [{'hashname': hashname, 'filemd5': filemd5} for hashname, filemd5 in path_md5.keys()]
    )


def get_package(conn, constraint_name):
    conn.execute('TRUNCATE TABLE IF EXISTS PkgTemp')
    sql = """INSERT INTO PkgTemp
SELECT pkghash, name, buildtime
FROM Package_buffer
WHERE pkghash IN (SELECT pkghash
                  FROM Assignment_buffer
                  WHERE uuid IN
                        (SELECT uuid
                         FROM AssignmentName
                         WHERE assignment_name IN %(constraint_name)s)) 
        AND notLike(name, '%%not-found%%') AND sourcepackage=%(srcp)s 
        AND pkghash IN (SELECT DISTINCT(pkghash) FROM File_buffer 
        WHERE (hashname, filemd5) IN (SELECT hashname, filemd5 FROM PathMd5Temp))"""

    conn.execute(sql, {'srcp': 0, 'constraint_name': constraint_name})


def get_file(conn):
    conn.execute('TRUNCATE TABLE IF EXISTS FileTemp')
    sql = """INSERT INTO FileTemp
SELECT pkghash, hashname, filemd5
FROM File_buffer
WHERE fileclass != 'directory'
  AND pkghash IN
      (SELECT pkghash FROM PkgTemp)"""
    conn.execute(sql)
