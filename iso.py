import argparse
import pycdlib
import os
import os.path
import rpm
import tempfile
import hashlib
import logging
import mmh3
import utils
from io import BytesIO
from collections import defaultdict
from PySquashfsImage import SquashFsImage
from extract import insert_assigment
from functools import reduce


log = logging.getLogger('extract')


def mmhash(val):
    a, b = mmh3.hash64(val, signed=False)
    return a ^ b


def process_iso(conn, iso, aname_id):
    for sqfs in ['/ALTINST.;1', '/LIVE.;1', '/RESCUE.;1']:
        tmp_file = tempfile.NamedTemporaryFile()
        try:
            iso.get_file_from_iso_fp(tmp_file, iso_path=sqfs)
        except pycdlib.pycdlibexception.PyCdlibInvalidInput as e:
            log.error(e)
            continue
        tmp_file.seek(0)
        m = hashlib.sha1()
        m.update(tmp_file.read())
        squash_sha1 = m.hexdigest()
        log.info('iso processing sqfs: {}, sha1: {}'.format(sqfs, squash_sha1))
        path_md5 = process_squashfs(tmp_file.name, squash_sha1) # {(filename, filemd5): {'data': ...}}
        log.info('iso read {} files'.format(len(path_md5)))
        packages = get_package(conn, path_md5) # [(pkghash, name, buildtime), ...]
        log.info('iso finded {} packages'.format(len(packages)))
        files = get_file(conn, packages) # {pkghash: {(filename, filemd5), ...}}
        assigments = make_assigments(path_md5, packages, files)
        log.info('iso saved: {}, assigments'.format(len(assigments)))
        insert_assigment(conn, aname_id, assigments)
        orphan_files = get_orphan_files(files, path_md5)
        make_orphan_package(conn, sqfs, squash_sha1)
        log.info('iso save: {}, orphan files'.format(len(orphan_files)))
        write_orphan_files(conn, orphan_files, path_md5)
        tmp_file.close()


def get_orphan_files(files, path_md5):
    f_all = reduce(lambda a, b: a | b, files.values())
    return path_md5.keys() - f_all


def make_orphan_package(conn, name, sha1):
    pkghash = mmhash(sha1)
    conn.execute('INSERT INTO Package_buffer (pkghash, name) VALUES', [{'pkghash': pkghash, 'name': name}])
    return pkghash


def write_orphan_files(conn, files, path_md5):
    sql = 'INSERT INTO File_buffer (filename, filelinkto, filemd5, pkghash, filesize, filemode, filemtime, fileusername, filegroupname, fileverifyflag, fileclass) VALUES'
    data = [v for k, v in path_md5.items() if k in files]
    conn.execute(sql, data)


def get_package_score(package_files, squash_files):
    if package_files:
        return len(package_files & squash_files) / len(package_files)
    return 0


def make_assigments(path_md5, packages, files):
    dups = {}
    for package, name, buildtime in packages:
        pkg_score = get_package_score(files[package], path_md5.keys())
        if pkg_score == 1.0:
            p = dups.get(name)
            if p is None:
                dups[name] = (buildtime, package)
            else:
                if buildtime > p[0]:
                    dups[name] = (buildtime, package)
    assigments = set([i[1] for i in dups.values()])
    return assigments


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
        data['pkghash'] = mmhash(squash_sha1)
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


def get_package(conn, path_md5):
    sql = 'SELECT pkghash, name, buildtime FROM Package_buffer WHERE sourcepackage=%(srcp)s AND pkghash IN (SELECT DISTINCT(pkghash) FROM File_buffer WHERE (filename, filemd5) IN %(path_md5)s)'
    result = set()
    for chunk in utils.chunks(path_md5.keys(), 1000):
        result.update(conn.execute(sql, {'path_md5': tuple(chunk), 'srcp': 0}))
    return result


def get_file(conn, packages):
    sql = "SELECT pkghash, filename, filemd5 FROM File_buffer WHERE fileclass != 'directory' AND pkghash IN %(pkghashes)s"
    result = []
    packages_hash = [i[0] for i in packages]
    for chunk in utils.chunks(packages_hash, 1000):
        result.extend(conn.execute(sql, {'pkghashes': tuple(chunk)}))
    files = defaultdict(set)
    for k, *v in result:
        files[k].add(tuple(v))
    return files
