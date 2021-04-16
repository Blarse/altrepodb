import argparse
import configparser
import logging
import os
import os.path
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
import datetime
import time

import clickhouse_driver as chd
import rpm

import json

import extract
# from extract import get_header, insert_package, init_cache, check_package
from utils import get_logger, cvt, md5_from_file, mmhash, sha256_from_file, cvt_ts_to_datetime, val_from_json_str, log_parser, cvt_datetime_local_to_utc

NAME = 'task'

os.environ['LANG'] = 'C'

log = logging.getLogger(NAME)


def get_client(args):
    return chd.Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password
    )


class Task:
    def __init__(self, conn, girar, task):
        self.girar = girar
        self.conn = conn
        self.task = task
        self.cache = extract.init_cache(self.conn)
        self.approvals = []
        self._load_approvals()

    def _load_approvals(self):
        # select from DB last approval state for given task
        pass

    def _calculate_hash_from_array_by_CH(self, hashes):
        sql = 'SELECT murmurHash3_64(%(hashes)s)'
        r = self.conn.execute(sql, {'hashes': hashes})
        return int(r[0][0])

    def _insert_log(self, log_name, log_hash, log_type, log_start_time):
        log_file = self.girar.get_file_path(log_name)
        log_parsed = log_parser(log, log_file, log_type, log_start_time)
        if log_parsed:
            self.conn.execute(
                'INSERT INTO TaskLogs_buffer (*) VALUES',
                [dict(tlog_hash=log_hash, tlog_line=l, tlog_ts=t, tlog_message=m) for l, t, m in log_parsed],
                settings={'types_check': True}
            )

    def _insert_package(self, pkg, srpm_hash, is_srpm=False):
        kw = {}
        hdr = self.girar.get_header(pkg)
        sha1 = bytes.fromhex(cvt(hdr[rpm.RPMDBI_SHA1HEADER]))
        pkg_hash = mmhash(sha1)
        kw['pkg_hash'] = pkg_hash
        kw['pkg_filename'] = Path(pkg).name
        if is_srpm:
            kw['pkg_sourcerpm'] = kw['pkg_filename']
            kw['pkg_srcrpm_hash'] = pkg_hash
        else:
            kw['pkg_srcrpm_hash'] = srpm_hash
        if not extract.check_package_in_cache(self.cache, pkg_hash):
            extract.insert_package(self.conn, hdr, **kw)
            extract.insert_pkg_hash_single(self.conn,
                {'mmh': pkg_hash,
                'sha1': sha1,
                'md5': md5_from_file(self.girar.get_file_path(pkg), as_bytes=True),
                'sha256': sha256_from_file(self.girar.get_file_path(pkg), as_bytes=True)}
            )
            log.info(f"add package: {sha1.hex()} : {kw['pkg_filename']}")
        return pkg_hash

    def _save_task(self):
        # 1 - proceed with TaskStates
        self.task['task_state']['task_eventlog_hash'] = []
        # 1.1 - save events logs
        for _, log_file, log_hash, _ in [_ for _ in self.task['logs'] if _[0] == 'events']:
            self.task['task_state']['task_eventlog_hash'].append(log_hash)
            self._insert_log(log_file, log_hash, 'events', None)
        # 1.2 - save current task state
        self.conn.execute(
            'INSERT INTO TaskStates (*) VALUES',
            [self.task['task_state']],
            settings={'types_check': True}
        )
        # 2 - proceed with TaskApprovals
        # 2.1 - collect task approvals from DB
        tapps = []
        keywords = ('task_id', 'subtask_id', 'tapp_type', 'tapp_revoked', 'tapp_date', 'tapp_name', 'tapp_message')
        res = self.conn.execute(
            """SELECT argMax(tuple(*), ts) FROM TaskApprovals
            WHERE task_id = %(task_id)s GROUP BY (subtask_id, tapp_name)""",
            {'task_id': self.task['task_state']['task_id']}
        )
        res = [_[0] for _ in res]
        # 2.2 - collect previous approvals that are not rewoked
        for tapp in res:
            d = dict(zip(keywords, tapp))
            if d['tapp_revoked'] == 0:
                del d['tapp_revoked']
                tapps.append(d)
        # 2.3 - find rewoked by compare DB and actual task approvals 
        for tapp in tapps:
            if tapp not in self.task['task_approvals']:
                tapp['tapp_revoked'] = 1
                tapp['tapp_date'] = cvt_datetime_local_to_utc(datetime.datetime.now())
                self.task['task_approvals'].append(tapp)
        # 2.4 - set 'tapp_rewoked' flag for new and not revoked ones
        for tapp in self.task['task_approvals']:
            if 'tapp_revoked' not in tapp:
                tapp['tapp_revoked'] = 0
        # 2.5 - load new approvals state to DB
        if self.task['task_approvals']:
            self.conn.execute(
                'INSERT INTO TaskApprovals (*) VALUES',
                self.task['task_approvals'],
                settings={'types_check': True}
            )
        # 3 - proceed with Tasks
        if self.task['tasks']:
            self.conn.execute(
                'INSERT INTO Tasks_buffer (*) VALUES',
                self.task['tasks'],
                settings={'types_check': True}
            )
        # 4 - proceed with TaskIterations
        for titer in self.task['task_iterations']:
            # 4.1 - load packages
            titer['titer_srcrpm_hash'] = 0
            titer['titer_pkgs_hash'] = []
            # 4.1.1 - load srpm package
            if titer['titer_srpm']:
                titer['titer_srcrpm_hash'] = self._insert_package(titer['titer_srpm'], 0 , is_srpm=True)
            # 4.1.2 - load binary packages
            for pkg in titer['titer_rpms']:
                titer['titer_pkgs_hash'].append(
                    self._insert_package(pkg, titer['titer_srcrpm_hash'], is_srpm=False)
                )
            # 4.2 - load build logs
            subtask = str(titer['subtask_id'])
            arch = titer['subtask_arch']
            titer['titer_buildlog_hash'] = 0
            titer['titer_srpmlog_hash'] = 0
            for log_type, log_file, log_hash, _ in [_ for _ in self.task['logs'] if _[0] in ('srpm', 'build')]:
                log_subtask, log_arch = log_file.split('/')[1:3]
                if log_subtask == subtask and log_arch == arch:
                    log_start_time = self.girar.get_file_mtime(log_file)
                    if log_type == 'srpm':
                        titer['titer_srpmlog_hash'] = log_hash
                    elif log_type == 'build':
                        titer['titer_buildlog_hash'] = log_hash
                    self._insert_log(log_file, log_hash, log_type, log_start_time)
            # 4.3 - load chroots
            if titer['titer_chroot_base']:
                self.conn.execute(
                    'INSERT INTO TaskChroots_buffer (*) VALUES',
                    [{'tch_chroot': titer['titer_chroot_base']}],
                    settings={'types_check': True}
                )
                titer['titer_chroot_base'] = self._calculate_hash_from_array_by_CH(titer['titer_chroot_base'])
            if titer['titer_chroot_br']:
                self.conn.execute(
                    'INSERT INTO TaskChroots_buffer (*) VALUES',
                    [{'tch_chroot': titer['titer_chroot_br']}],
                    settings={'types_check': True}
                )
                titer['titer_chroot_br'] = self._calculate_hash_from_array_by_CH(titer['titer_chroot_br'])
            # 4.4 - load task iteration
            self.conn.execute(
                'INSERT INTO TaskIterations_buffer (*) VALUES',
                [titer],
                settings={'types_check': True}
            )
        # 5 - load arepo packages
        for pkg in self.task['arepo']:
            self._insert_package(pkg, 0, is_srpm=False)

    def save(self):
        self._save_task()

class Task2:
    def __init__(self, conn, girar):
        self.girar = girar
        self.conn = conn
        self.cache = extract.init_cache(self.conn)
        self._prepare_fields()

    def _prepare_fields(self):
        self.fields = {
            'task_id': int(self.girar.get('task/id').strip()),
            'try': int(self.girar.get('task/try').strip()),
            'iteration': int(self.girar.get('task/iter').strip()),
            'status': self.girar.get('task/state').strip(),
            'is_test': self.girar.get('task/test-only', status=True),
            'branch': self.girar.get('task/repo').strip()
        }

    def _get_gears_info(self, n):
        userid = self.girar.get('gears/{0}/userid'.format(n))
        userid = userid.strip() if userid else ''
        dir_ = self.girar.get('gears/{0}/dir'.format(n))
        dir_ = dir_.strip() if dir_ else ''
        tag_name = self.girar.get('gears/{0}/tag_name'.format(n))
        tag_name = tag_name.strip() if tag_name else ''
        tag_id = self.girar.get('gears/{0}/tag_id'.format(n))
        tag_id = tag_id.strip() if tag_id else ''
        tag_author = self.girar.get('gears/{0}/tag_author'.format(n))
        tag_author = tag_author.strip() if tag_author else ''
        srpm = self.girar.get('gears/{0}/srpm'.format(n))
        srpm = srpm.strip() if srpm else ''
        try:
            type_, hash_ = self.girar.get('gears/{0}/sid'.format(n)).strip().split(':')
        except Exception as error:
            log.error(error)
            type_ = 'gear' if srpm == '' else 'srpm'
            hash_ = ''

        fields = dict(
            userid=userid,
            dir=dir_,
            tag_name=tag_name,
            tag_id=tag_id,
            tag_author=tag_author,
            srpm=srpm,
            type=type_,
            hash=hash_
        )
        return fields

    def _get_pkg_list(self, method):
        try:
            return [i.split('\t') for i in self.girar.get(method).split('\n') if len(i) > 0]
        except Exception as error:
            log.error(error)
            return []

    def _get_chroot_list(self, subtask, arch, chroot):
        method = 'build/{0}/{1}/{2}'.format(subtask, arch, chroot)
        try:
            content = self.girar.get(method)
            if content is not None:
                return [i.split('\t')[-1].strip() for i in content.split('\n') if len(i) > 0]
        except Exception as error:
            log.error(error)
        return []

    def _get_archs_list(self):
        return [i.strip() for i in self.girar.get('plan/change-arch').split('\n') if len(i) > 0]

    def _check_task(self):
        sql = ("SELECT COUNT(*) "
        "FROM Tasks WHERE task_id = %(task_id)s "
        "AND try = %(try)s "
        "AND iteration = %(iteration)s")
        already = self.conn.execute(sql, {'task_id': self.fields['task_id'], 'try': self.fields['try'], 'iteration': self.fields['iteration']})
        return already[0][0] > 0
        # return False

    def _save_task(self):
        if self._check_task():
            log.info('Task {0} already exist'.format(self.fields['task_id']))
            return
        src_pkgs = self._get_src()
        bin_pkgs = self._get_bin(src_pkgs)
        archs = self._get_archs_list()
        tasks = []
        for subtask, sha1 in src_pkgs.items():
            task = self.fields.copy()
            task.update(self._get_gears_info(subtask))
            task['subtask'] = int(subtask)
            task['sourcepkg_hash'] = mmhash(sha1)
            for arch in archs:
                task_ = task.copy()
                task_['task_arch'] = arch
                task_['pkgs'] = [mmhash(p) for p in bin_pkgs[subtask][arch]]
                # skip packages, that are not build for arch
                if len(task_['pkgs']) == 0:
                    continue
                task_['chroot_base'] = [mmhash(p) for p in self._get_chroot_list(subtask, arch, 'chroot_base')]
                task_['chroot_BR'] = [mmhash(p) for p in self._get_chroot_list(subtask, arch, 'chroot_BR')]
                tasks.append(task_)
        sql = """INSERT INTO Tasks (task_id, subtask, sourcepkg_hash, try, iteration, status,
                   is_test, branch, pkgs, userid, dir, tag_name, tag_id,
                   tag_author, srpm, type, hash, task_arch, chroot_base,
                   chroot_BR) VALUES"""
        self.conn.execute(sql, tasks)
        log.info('save task={0} try={1} iter={2}'.format(self.fields['task_id'], self.fields['try'], self.fields['iteration']))

    def _get_src(self):
        src_list = self._get_pkg_list('plan/add-src')
        src_pkgs = {}
        for *_, pkg, n in src_list:
            kw = {}
            hdr = self.girar.get_header(pkg)
            sha1 = bytes.fromhex(cvt(hdr[rpm.RPMDBI_SHA1HEADER]))
            pkghash = mmhash(sha1)
            kw['pkg_hash'] = pkghash
            kw['pkg_srcrpm_hash'] = pkghash
            kw['pkg_filename'] = Path(pkg).name
            kw['pkg_sourcerpm'] = Path(pkg).name
            # if not extract.check_package(self.cache, hdr):
            if not extract.check_package_in_cache(self.cache, pkghash):
                extract.insert_package(self.conn, hdr, **kw)
                extract.insert_pkg_hash_single(self.conn,
                    {'mmh': pkghash,
                    'sha1': sha1,
                    'md5': md5_from_file(self.girar.get_file_path(pkg), as_bytes=True),
                    'sha256': sha256_from_file(self.girar.get_file_path(pkg), as_bytes=True)}
                )
                log.info('add src package: {0}'.format(sha1.hex()))
            src_pkgs[n] = sha1
        return src_pkgs

    def _get_bin(self, src):
        bin_list = self._get_pkg_list('plan/add-bin')
        bin_pkgs = defaultdict(lambda: defaultdict(list))
        for _, _, arch, _, pkg, n, *_ in bin_list:
            kw = {}
            hdr = self.girar.get_header(pkg)
            sha1 = bytes.fromhex(cvt(hdr[rpm.RPMDBI_SHA1HEADER]))
            pkghash = mmhash(sha1)
            kw['pkg_hash'] = pkghash
            kw['pkg_srcrpm_hash'] = mmhash(src[n])
            kw['pkg_filename'] = Path(pkg).name
            # if not extract.check_package(self.cache, hdr):
            if not extract.check_package_in_cache(self.cache, pkghash):
                extract.insert_package(self.conn, hdr, **kw)
                extract.insert_pkg_hash_single(self.conn,
                    {'mmh': pkghash,
                    'sha1': sha1,
                    'md5': md5_from_file(self.girar.get_file_path(pkg), as_bytes=True),
                    'sha256': sha256_from_file(self.girar.get_file_path(pkg), as_bytes=True)}
                )
                log.info('add bin package: {0}'.format(sha1.hex()))
            bin_pkgs[n][arch].append(sha1)
        return bin_pkgs

    def save(self):
        self._save_task()


class Girar:
    def __init__(self, url):
        self.url = url
        self.ts = rpm.TransactionSet()

    def _get_content(self, url, status=False):
        try:
            r = urllib.request.urlopen(url)
        except urllib.error.URLError as e:
            log.debug('{0} - {1}'.format(e, url))
            if status:
                return False
            return None
        except Exception as e:
            log.error('{0} - {1}'.format(e, url))
            return None
        if r.getcode() == 200:
            if status:
                return True
            return cvt(r.read())

    def get(self, method, status=False):
        p = os.path.join(self.url, method)
        r = self._get_content(p, status)
        return r

    def check(self):
        return self._get_content(self.url, status=True)

    def get_header(self, path):
        return extract.get_header(self.ts, os.path.join(self.url, path))


class TaskFromFS:
    def __init__(self, url):
        self.url = Path(url)
        self.ts = rpm.TransactionSet()

    def _get_content(self, url, status=False):
        r = None
        if status:
            if Path(url).exists():
                return True
            else:
                return False
        try:
            r = Path(url).read_bytes()
        except IsADirectoryError:
            # return directory listing
            return [_ for _ in Path(url).iterdir()]
        except FileNotFoundError as e:
            log.debug(f"{e} - {url}")
            return None
        except Exception as e:
            log.error(f"{e} - {url}")
            return None
        return r

    def get(self, path):
        p = Path.joinpath(self.url, path)
        r = self._get_content(p, status=False)
        return cvt(r)

    def check(self):
        return self._get_content(self.url, status=True)

    def check_file(self, path):
        p = Path.joinpath(self.url, path)
        return self._get_content(p, status=True)

    def get_bytes(self, path):
        p = Path.joinpath(self.url, path)
        r = self._get_content(p, status=False)
        return r

    def get_file_mtime(self, path):
        p = Path.joinpath(self.url, path)
        try:
            mtime = p.stat().st_mtime
        except FileNotFoundError:
            return None
        return cvt_ts_to_datetime(mtime, use_local_tz=False)

    def get_header(self, path):
        log.debug(f"reading header for {path}")
        return extract.get_header(self.ts, str(Path.joinpath(self.url, path)))

    def get_file_path(self, path):
        return Path.joinpath(self.url, path)

    def file_exists_and_not_empty(self, path):
        p = Path.joinpath(self.url, path)
        if p.is_file() and p.stat().st_size > 0:
            return True
        else:
            return False

    def get_symlink_target(self, path, name_only=False):
        symlink = Path.joinpath(self.url, path)
        if symlink.is_symlink():
            if name_only:
                return str(symlink.resolve().name)
            else:
                return str(symlink.resolve())
        else:
            return None

    def parse_approval_file(self, path):
        p = Path.joinpath(self.url, path)
        r = self._get_content(p, status=False)
        n = d = m = None
        if r:
            r = cvt(r)
            try:
                d, *m = [_ for _ in r.split('\n') if len(_) >0]
                d, n = [_.strip() for _ in d.split('::') if len(_) >0]
                n = n.split(' ')[-1]
                d = datetime.datetime.strptime(d, '%Y-%b-%d %H:%M:%S')
                m = '\n'.join((_ for _ in m))
                return (n, d, m)
            except Exception as e:
                log.error(f"File parsing failed with error {e} for '{path}' contains '{r}'")
        return None


def init_task_structure_from_task(girar):
    """Loads all available contents from task to dictionary

    Args:
        girar (class): Girar class instance initialized with exact task

    Returns:
        dict: parsed task structure with contents
    """
    task = {
        'tasks': [],
        'task_state': {},
        'task_approvals': [],
        'task_iterations': [],
        'arepo': [],
        'logs': []
    }
    # parse '/task' and '/info.json' for 'TaskStates'
    if girar.check_file('task/state'):
        task['task_state']['task_changed'] = girar.get_file_mtime('task/state')
    else:
        # skip tasks with uncertain state for God sake
        return task
    task['task_state']['task_id'] = int(girar.get_file_path('').name)
    t = girar.get('task/state')
    task['task_state']['task_state'] = t.strip() if t else ''
    t = girar.get('task/run')
    task['task_state']['task_runby'] = t.strip() if t else ''
    t = girar.get('task/depends')
    task['task_state']['task_depends'] = [int(_) for _ in t.split('\n') if len(_) > 0] if t else []
    t = girar.get('task/try')
    task['task_state']['task_try'] = int(t.strip()) if t else 0
    task['task_state']['task_testonly'] = 1 if girar.check_file('task/test-only') else 0
    task['task_state']['task_failearly'] = 1 if girar.check_file('task/fail-early') else 0
    t  = val_from_json_str(girar.get('info.json'), 'shared')
    task['task_state']['task_shared'] = 1 if t else 0
    t = girar.get('task/message')
    task['task_state']['task_message'] = t.strip() if t else ''
    t = girar.get('task/version')
    task['task_state']['task_version'] = t.strip() if t else ''
    t = girar.get_symlink_target('build/repo/prev', name_only=True)
    task['task_state']['task_prev'] = int(t.strip()) if t else 0
    # parse '/acl' for 'TaskApprovals'
    # 0 - iterate through 'acl/approved'
    for subtask in (_.name for _ in girar.get('acl/approved') if _.is_dir()):
        subtask_dir = '/'.join(('acl/approved', subtask))
        for approver in (_.name for _ in girar.get(subtask_dir) if _.is_file()):
            t = girar.parse_approval_file('/'.join((subtask_dir, approver)))
            if t:
                approval = {
                    'task_id': task['task_state']['task_id'],
                    'subtask_id': int(subtask),
                    'tapp_type': 'approve',
                    # 'tapp_revoked': None,
                    'tapp_name': t[0],
                    'tapp_date': t[1],
                    'tapp_message': t[2]
                    }
                task['task_approvals'].append(approval)
    # 1 - iterate through 'acl/dsiapproved'
    for subtask in (_.name for _ in girar.get_file_path('acl/disapproved').glob('[0-7]*') if _.is_dir()):
        subtask_dir = '/'.join(('acl/disapproved', subtask))
        for approver in (_.name for _ in girar.get(subtask_dir) if _.is_file()):
            t = girar.parse_approval_file('/'.join((subtask_dir, approver)))
            if t:
                approval = {
                    'task_id': task['task_state']['task_id'],
                    'subtask_id': int(subtask),
                    'tapp_type': 'disapprove',
                    # 'tapp_revoked': None,
                    'tapp_name': t[0],
                    'tapp_date': t[1],
                    'tapp_message': t[2]
                    }
                task['task_approvals'].append(approval)
    # parse '/gears' for 'Tasks'
    for subtask in (_.name for _ in girar.get_file_path('gears').glob('[0-7]*') if _.is_dir()):
        subtask_dir = '/'.join(('gears', subtask))
        files = set((_.name for _ in girar.get(subtask_dir)))
        sid = girar.get('/'.join((subtask_dir, 'sid')))

        subtask_dict ={
                'task_id': task['task_state']['task_id'],
                'subtask_id': int(subtask),
                'task_repo': girar.get('task/repo').strip(),
                'task_owner': girar.get('task/owner').strip(),
                'subtask_changed': None,
                'subtask_userid': girar.get('/'.join((subtask_dir, 'userid'))).strip(),
                'subtask_sid': sid.split(':')[1].strip() if sid else '',
                'subtask_dir': '',
                'subtask_package': '',
                'subtask_type': sid.split(':')[0]  if sid else '',
                'subtask_pkg_from': '',
                'subtask_tag_author': '',
                'subtask_tag_id': '',
                'subtask_tag_name': '',
                'subtask_srpm': '',
                'subtask_srpm_name': '',
                'subtask_srpm_evr': ''
        }

        if girar.check_file('/'.join((subtask_dir, 'userid'))):
            subtask_dict['subtask_changed'] = girar.get_file_mtime('/'.join((subtask_dir, 'userid')))
        else:
            subtask_dict['subtask_changed'] = girar.get_file_mtime(subtask_dir)

        if 'dir' not in files and 'srpm' not in files and 'package' not in files:
            # deleted subtask
            subtask_dict['subtask_deleted'] = 1
        else:
            subtask_dict['subtask_deleted'] = 0
            # logic from girar-task-run check_copy_del()
            if girar.file_exists_and_not_empty('/'.join((subtask_dir, 'package'))) \
                and not girar.file_exists_and_not_empty('/'.join((subtask_dir, 'dir'))):
                if girar.file_exists_and_not_empty('/'.join((subtask_dir, 'copy_repo'))):
                    t = girar.get('/'.join((subtask_dir, 'copy_repo')))
                    subtask_dict['subtask_type'] = 'copy'
                    subtask_dict['subtask_pkg_from'] = t.strip()
                else:
                    subtask_dict['subtask_type'] = 'delete'

            if girar.check_file('/'.join((subtask_dir, 'rebuild'))):
                t = girar.get('/'.join((subtask_dir, 'rebuild')))
                subtask_dict['subtask_type'] = 'rebuild'
                subtask_dict['subtask_pkg_from'] = t.strip()

            t = girar.get('/'.join((subtask_dir, 'dir')))
            subtask_dict['subtask_dir'] = t.strip() if t else ''
            t = girar.get('/'.join((subtask_dir, 'package')))
            subtask_dict['subtask_package'] = t.strip() if t else ''
            t = girar.get('/'.join((subtask_dir, 'tag_author')))
            subtask_dict['subtask_tag_author'] = t.strip() if t else ''
            t = girar.get('/'.join((subtask_dir, 'tag_id')))
            subtask_dict['subtask_tag_id'] = t.strip() if t else ''
            t = girar.get('/'.join((subtask_dir, 'tag_name')))
            subtask_dict['subtask_tag_name'] = t.strip() if t else ''
            t = girar.get('/'.join((subtask_dir, 'srpm')))
            subtask_dict['subtask_srpm'] = t.strip() if t else ''
            t = girar.get('/'.join((subtask_dir, 'nevr')))
            if t:
                subtask_dict['subtask_srpm_name'] = t.split('\t')[0].strip()
                subtask_dict['subtask_srpm_evr'] = t.split('\t')[1].strip()
        task['tasks'].append(subtask_dict)
    # parse '/build' for 'TaskIterations'
    # 0 - get src and packages from plan
    src_pkgs = {}
    bin_pkgs = defaultdict(lambda: defaultdict(list))
    t = girar.get('plan/add-src')
    if t:
        for *_, pkg, n in [_.split('\t') for _ in t.split('\n') if len(_) > 0]:
            src_pkgs[n] = pkg
    t = girar.get('plan/add-bin')
    if t:
        for _, _, arch, _, pkg, n, *_ in [_.split('\t') for _ in t.split('\n') if len(_) > 0]:
            bin_pkgs[n][arch].append(pkg)
    # 1 - get contents from /build/%subtask_id%/%arch%
    for subtask in (_.name for _ in girar.get_file_path('build').glob('[0-7]*') if _.is_dir()):
        subtask_dir = '/'.join(('build', subtask))
        archs = set((_.name for _ in girar.get(subtask_dir) if _.is_dir()))
        for arch in archs:
            arch_dir = '/'.join((subtask_dir, arch))
            build_dict = {
                'task_id': task['task_state']['task_id'],
                'subtask_id': int(subtask),
                'subtask_arch': arch,
                'titer_ts': None,
                'titer_status': None,
                'task_try': None,
                'task_iter': None,
                'titer_srpm': None, # 'titer_srcrpm_hash'
                'titer_rpms': [],   # 'titer_pkgs_hash'
                'titer_chroot_base': [],
                'titer_chroot_br': []
            }
            if girar.check_file('/'.join((arch_dir, 'status'))):
                t = girar.get_file_mtime('/'.join((arch_dir, 'status')))
                tt = girar.get('/'.join((arch_dir, 'status')))
                build_dict['titer_status'] = tt.strip() if tt else 'failed'
            else:
                t = girar.get_file_mtime(arch_dir)
                build_dict['titer_status'] = 'failed'
            build_dict['titer_ts'] = t
            t = girar.get('task/try')
            build_dict['task_try'] = int(t.strip()) if t else 0
            t = girar.get('task/iter')
            build_dict['task_iter'] = int(t.strip()) if t else 0
            # read chroots
            t = girar.get('/'.join((arch_dir, 'chroot_base')))
            if t:
                for pkg in (_.split('\t')[-1].strip() for _ in t.split('\n') if len(_) > 0):
                    build_dict['titer_chroot_base'].append(mmhash(bytes.fromhex(pkg)))
            t = girar.get('/'.join((arch_dir, 'chroot_BR')))
            if t:
                for pkg in (_.split('\t')[-1].strip() for _ in t.split('\n') if len(_) > 0):
                    build_dict['titer_chroot_br'].append(mmhash(bytes.fromhex(pkg)))
            # get src and bin packages
            t = girar.get('/'.join((arch_dir, 'srpm')))
            if t and len(t) > 0:
                build_dict['titer_status'] = 'built'
                src_pkgs[subtask] = '/'.join((arch_dir, 'srpm', t[0].name))
            if subtask in src_pkgs:
                build_dict['titer_srpm'] = src_pkgs[subtask]

            t = girar.get('/'.join((arch_dir, 'rpms')))
            if t and len(t) > 0:
                build_dict['titer_status'] = 'built'
                bin_pkgs[subtask][arch] = []
                for brpm in t:
                    bin_pkgs[subtask][arch].append('/'.join((arch_dir, 'rpms', brpm.name)))

            if subtask in bin_pkgs and arch in bin_pkgs[subtask]:
                build_dict['titer_rpms'] = [_ for _ in bin_pkgs[subtask][arch]]
            task['task_iterations'].append(build_dict)
            # save build logs
            for log_file in ('log', 'srpm.log'):
                if girar.file_exists_and_not_empty('/'.join((arch_dir, log_file))):
                    log_hash = (''
                        + str(build_dict['task_id'])
                        + str(build_dict['subtask_id'])
                        + str(build_dict['task_try'])
                        + str(build_dict['task_iter'])
                        + build_dict['subtask_arch']
                    )
                    if log_file == 'log':
                        log_hash = 'build' + log_hash
                        task['logs'].append((
                            'build',
                            '/'.join((arch_dir, log_file)),
                            mmhash(log_hash),
                            log_hash
                        ))
                    else:
                        log_hash = 'srpm'  + log_hash
                        task['logs'].append((
                            'srpm',
                            '/'.join((arch_dir, log_file)),
                            mmhash(log_hash),
                            log_hash
                        ))
    # parse '/arepo' for packages
    t = girar.get('arepo/x86_64-i586/rpms')
    for pkg in (_.name for _ in t if t and _.suffix == '.rpm'):
            task['arepo'].append(f"arepo/x86_64-i586/rpms/{pkg}")
    # parse '/logs' for event logs
    for log_file in (_.name for _ in girar.get_file_path('logs').glob('events.*.log')):
        log_hash = (
            'events'
            + str(task['task_state']['task_id'])
            + log_file.split('.')[1]
            + log_file.split('.')[2]
        )
        task['logs'].append((
            'events',
            '/'.join(('logs', log_file)),
            mmhash(log_hash),
            log_hash
        ))

    return task

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str, help='git.altlinux task url')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--dbname', type=str, help='Database name')
    parser.add_argument('-s', '--host', type=str, help='Database host')
    parser.add_argument('-p', '--port', type=str, help='Database password')
    parser.add_argument('-u', '--user', type=str, help='Database login')
    parser.add_argument('-P', '--password', type=str, help='Database password')
    parser.add_argument('-D', '--dumpjson', action='store_true', help='Dump parsed task structure to JSON file')
    args = parser.parse_args()
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        if cfg.has_section('DATABASE'):
            section_db = cfg['DATABASE']
            args.dbname = args.dbname or section_db.get('dbname', 'default')
            args.host = args.host or section_db.get('host', 'localhost')
            args.port = args.port or section_db.get('port', None)
            args.user = args.user or section_db.get('user', 'default')
            args.password = args.password or section_db.get('password', '')
    else:
        args.dbname = args.dbname or 'default'
        args.host = args.host or 'localhost'
        args.port = args.port or None
        args.user = args.user or 'default'
        args.password = args.password or ''
    return args


def load(args, conn):
    # girar = Girar(args.url)
    girar = TaskFromFS(args.url)
    if girar.check():
        ts = time.time()
        log.info(f"reading task structure for {args.url}")
        task_struct = init_task_structure_from_task(girar)
        if args.dumpjson:
            Path.joinpath(
                Path.cwd(),
                f"dump-{str(task_struct['task_state']['task_id'])}-{datetime.date.today().strftime('%Y-%m-%d')}.json"
            ).write_text(
                json.dumps(task_struct, indent=2, sort_keys=True, default=str)
            )
        task = Task(conn, girar, task_struct)
        log.info(f"loading {task_struct['task_state']['task_id']} to database {args.dbname}")
        task.save()
        ts = time.time() - ts
        log.info(F"task {task_struct['task_state']['task_id']} loaded in {ts:.3f} seconds")
    else:
        raise ValueError('task not found: {0}'.format(args.url))


def main():
    args = get_args()
    if args.url.endswith('/'):
        args.url = args.url[:-1]
    logger = get_logger(NAME, tag=(args.url.split('/')[-1]))
    logger.setLevel(logging.DEBUG)
    conn = None
    try:
        conn = get_client(args)
        # if not check_latest_version(conn):
        #     raise RuntimeError('incorrect database schema version')
        load(args, conn)
    except Exception as error:
        logger.error(error, exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()


if __name__ == '__main__':
    main()
