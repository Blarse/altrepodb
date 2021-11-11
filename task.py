import argparse
import configparser
import logging
import os
import os.path
import sys
import urllib.error
import urllib.request
from collections import defaultdict, namedtuple
from pathlib import Path
import datetime
import time
import traceback
import threading
import rpm
import json
import clickhouse_driver as chd
from copy import deepcopy

import extract

# from extract import get_header, insert_package, init_cache, check_package
from utils import get_logger, cvt, mmhash, md5_from_file, sha256_from_file
from utils import (
    cvt_ts_to_datetime,
    val_from_json_str,
    log_parser,
    cvt_datetime_local_to_utc,
)
from utils import parse_hash_diff, parse_pkglist_diff, LockedIterator, GeneratorWrapper
from utils import set_datetime_timezone_to_utc

NAME = "task"

os.environ["LANG"] = "C"

log = logging.getLogger(NAME)


class RaisingThreadError(Exception):
    """Custom exception class used in RaisingThread subclasses

    Args:
        message (string): exception message
        traceback (string): traceback of exception that raised in thread
    """

    def __init__(self, message=None, traceback=None) -> None:
        self.message: str = message
        self.traceback: str = traceback
        super().__init__()


class RaisingTread(threading.Thread):
    """Base threading class that raises exception stored in self.exc at join()"""

    def __init__(self, *args, **kwargs):
        self.exc: Exception = None
        self.exc_message: str = None
        self.exc_traceback: str = None
        super().__init__(*args, **kwargs)

    def join(self):
        super().join()
        if self.exc:
            raise RaisingThreadError(
                message=self.exc_message, traceback=self.exc_traceback
            ) from self.exc


def get_client(args):
    return chd.Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password,
    )


def init_cache(conn, packages):
    result = conn.execute(
        """CREATE TEMPORARY TABLE IF NOT EXISTS PkgFNameTmp (pkg_filename String)"""
    )
    payload = []
    for pkg_name in [_.split("/")[-1] for _ in packages]:
        payload.append({"pkg_filename": pkg_name})

    result = conn.execute("INSERT INTO PkgFNameTmp (*) VALUES", payload)

    log.debug(f"Inserted {len(payload)} 'pkg_filename's into PkgFNameTmp")

    result = conn.execute(
        """SELECT pkg_hash
           FROM Packages_buffer
           WHERE pkg_filename IN
             (SELECT * FROM PkgFNameTmp)"""
    )

    return {i[0] for i in result}


class LogLoaderWorker(RaisingTread):
    def __init__(self, conn, girar, logger, logs, count_list, *args, **kwargs) -> None:
        self.conn = conn
        self.girar = girar
        self.logger = logger
        self.logs = logs
        self.count_list = count_list
        self.lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def run(self):
        self.logger.debug(f"thread {self.ident} start")
        count = 0
        for log in self.logs:
            try:
                st = time.time()
                log_type, log_name, log_hash, _ = log
                # log_subtask, log_arch = log_file.split('/')[1:3]
                log_start_time = self.girar.get_file_mtime(log_name)
                log_file_size = self.girar.get_file_size(log_name)
                log_file = self.girar.get_file_path(log_name)
                log_parsed = GeneratorWrapper(
                    log_parser(self.logger, log_file, log_type, log_start_time)
                )
                if log_parsed:
                    count += 1
                    self.conn.execute(
                        "INSERT INTO TaskLogs_buffer (*) VALUES",
                        (
                            dict(
                                tlog_hash=log_hash,
                                tlog_line=l,
                                tlog_ts=t,
                                tlog_message=m,
                            )
                            for l, t, m in log_parsed
                        ),
                    )
                    self.logger.debug(
                        f"Logfile loaded in {(time.time() - st):.3f} seconds : {log_name} : {log_file_size} bytes"
                    )
                else:
                    self.logger.debug(f"Logfile parsing failed for {log_name}")
            except Exception as error:
                self.logger.error(error, exc_info=True)
                self.exc = error
                self.exc_message = f"Exception in thread {self.name} for log {log_name}"
                self.exc_traceback = traceback.format_exc()
                break
        self.logger.debug("thread {self.ident} stop")
        self.count_list.append(count)


def log_load_worker_pool(args, girar, logger, logs_list, num_of_workers=None):
    st = time.time()
    workers = []
    connections = []
    logs = LockedIterator((log for log in logs_list))
    logs_count = []
    if num_of_workers:
        args.workers = num_of_workers

    for i in range(args.workers):
        conn = get_client(args)
        connections.append(conn)
        worker = LogLoaderWorker(conn, girar, logger, logs, logs_count)
        worker.start()
        workers.append(worker)

    for w in workers:
        try:
            w.join()
        except RaisingThreadError as e:
            logger.error(e.message)
            # print(e.traceback)
            raise e

    for c in connections:
        if c is not None:
            c.disconnect()

    logger.info(
        f"{sum(logs_count)} log files loaded in {(time.time() - st):.3f} seconds"
    )


class TaskIterationLoaderWorker(RaisingTread):
    def __init__(
        self,
        conn,
        girar,
        logger,
        pkg_hashes_cache,
        task_pkg_hashes,
        task_logs,
        task_iterations,
        count_list,
        force_load,
        *args,
        **kwargs,
    ) -> None:
        self.conn = conn
        self.girar = girar
        self.logger = logger
        self.cache = pkg_hashes_cache
        self.pkg_hashes = task_pkg_hashes
        self.task_logs = task_logs
        self.titers = task_iterations
        self.count_list = count_list
        self.count = 0
        self.force = force_load
        self.lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def _calculate_hash_from_array_by_CH(self, hashes):
        sql = "SELECT murmurHash3_64(%(hashes)s)"
        r = self.conn.execute(sql, {"hashes": hashes})
        return int(r[0][0])

    def _insert_package(self, pkg, srpm_hash, is_srpm):
        st = time.time()
        kw = {}
        hdr = self.girar.get_header(pkg)
        sha1 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_SHA1HEADER]))
        hashes = {"sha1": sha1, "mmh": mmhash(sha1)}
        pkg_name = Path(pkg).name

        if self.pkg_hashes[pkg_name]["md5"]:
            hashes["md5"] = self.pkg_hashes[pkg_name]["md5"]
        else:
            self.logger.debug(f"calculate MD5 for {pkg_name} file")
            hashes["md5"] = md5_from_file(self.girar.get_file_path(pkg), as_bytes=True)

        if self.pkg_hashes[pkg_name]["sha256"]:
            hashes["sha256"] = self.pkg_hashes[pkg_name]["sha256"]
        else:
            self.logger.debug(f"calculate SHA256 for {pkg_name} file")
            hashes["sha256"] = sha256_from_file(
                self.girar.get_file_path(pkg), as_bytes=True
            )

        kw["pkg_hash"] = hashes["mmh"]
        kw["pkg_filename"] = pkg_name
        kw["pkg_filesize"] = self.girar.get_file_size(pkg)
        if is_srpm:
            kw["pkg_sourcerpm"] = pkg_name
            kw["pkg_srcrpm_hash"] = hashes["mmh"]
        else:
            kw["pkg_srcrpm_hash"] = srpm_hash

        if self.force or not extract.check_package_in_cache(self.cache, hashes["mmh"]):
            extract.insert_package(self.conn, hdr, self.girar.get_file_path(pkg), **kw)
            extract.insert_pkg_hash_single(self.conn, hashes)
            self.cache.add(hashes["mmh"])
            self.count += 1
            self.logger.debug(
                f"package loaded in {(time.time() - st):.3f} seconds : {hashes['sha1'].hex()} : {kw['pkg_filename']}"
            )
        else:
            self.logger.debug(
                f"package already loaded : {hashes['sha1'].hex()} : {kw['pkg_filename']}"
            )

        return hashes["mmh"]

    def run(self):
        self.logger.debug(f"thread {self.ident} start")
        count = 0
        for titer in self.titers:
            try:
                # 1 - load packages
                titer["titer_srcrpm_hash"] = 0
                titer["titer_pkgs_hash"] = []
                subtask = str(titer["subtask_id"])
                arch = titer["subtask_arch"]
                # 1.1 - load srpm package
                with self.lock:
                    if titer["titer_srpm"]:
                        titer["titer_srcrpm_hash"] = self._insert_package(
                            titer["titer_srpm"], 0, is_srpm=True
                        )
                    else:
                        titer["titer_srcrpm_hash"] = 0
                # 1.2 - load binary packages
                for pkg in titer["titer_rpms"]:
                    titer["titer_pkgs_hash"].append(
                        self._insert_package(
                            pkg, titer["titer_srcrpm_hash"], is_srpm=False
                        )
                    )

                if not titer["titer_pkgs_hash"]:
                    titer["titer_pkgs_hash"] = [0]
                # 2 - save build log hashes
                titer["titer_buildlog_hash"] = 0
                titer["titer_srpmlog_hash"] = 0
                for log_type, log_file, log_hash, _ in [
                    _ for _ in self.task_logs if _[0] in ("srpm", "build")
                ]:
                    log_subtask, log_arch = log_file.split("/")[1:3]
                    if log_subtask == subtask and log_arch == arch:
                        if log_type == "srpm":
                            titer["titer_srpmlog_hash"] = log_hash
                        elif log_type == "build":
                            titer["titer_buildlog_hash"] = log_hash
                # 3 - load chroots
                if titer["titer_chroot_base"]:
                    self.conn.execute(
                        "INSERT INTO TaskChroots_buffer (*) VALUES",
                        [{"tch_chroot": titer["titer_chroot_base"]}],
                    )
                    titer["titer_chroot_base"] = self._calculate_hash_from_array_by_CH(
                        titer["titer_chroot_base"]
                    )
                else:
                    titer["titer_chroot_base"] = 0
                if titer["titer_chroot_br"]:
                    self.conn.execute(
                        "INSERT INTO TaskChroots_buffer (*) VALUES",
                        [{"tch_chroot": titer["titer_chroot_br"]}],
                    )
                    titer["titer_chroot_br"] = self._calculate_hash_from_array_by_CH(
                        titer["titer_chroot_br"]
                    )
                else:
                    titer["titer_chroot_br"] = 0
                # 4 - load task iteration
                self.conn.execute(
                    "INSERT INTO TaskIterations_buffer (*) VALUES", [titer]
                )
                count += 1
            except Exception as error:
                self.logger.error(error, exc_info=True)
                self.exc = error
                self.exc_message = f"Exception in thread {self.name} for task iteration {titer['task_id']} {titer['subtask_id']}"
                self.exc_traceback = traceback.format_exc()
                break
        if self.count:
            self.logger.info(
                f"{self.count} packages loaded from /build/{subtask}/{arch}"
            )
        self.logger.debug(f"thread {self.ident} stop")
        self.count_list.append(count)


def titer_load_worker_pool(
    args,
    conn,
    girar,
    logger,
    task_pkg_hashes,
    task_logs,
    task_iterations,
    num_of_workers=None,
):
    st = time.time()
    workers = []
    connections = []
    titer_count = []
    titers = LockedIterator((titer for titer in task_iterations))

    if num_of_workers:
        args.workers = num_of_workers

    packages_ = []
    for titer in task_iterations:
        if titer["titer_srpm"]:
            packages_.append(titer["titer_srpm"])
        for pkg in titer["titer_rpms"]:
            packages_.append(pkg)

    pkg_hashes_cache = init_cache(conn, packages_)

    for i in range(args.workers):
        conn = get_client(args)
        connections.append(conn)
        worker = TaskIterationLoaderWorker(
            conn,
            girar,
            logger,
            pkg_hashes_cache,
            task_pkg_hashes,
            task_logs,
            titers,
            titer_count,
            args.force,
        )
        worker.start()
        workers.append(worker)

    for w in workers:
        try:
            w.join()
        except RaisingThreadError as e:
            logger.error(e.message)
            # print(e.traceback)
            raise e

    for c in connections:
        if c is not None:
            c.disconnect()

    logger.info(
        f"{sum(titer_count)} TaskIteration loaded in {(time.time() - st):.3f} seconds"
    )


class PackageLoaderWorker(RaisingTread):
    def __init__(
        self,
        conn,
        girar,
        logger,
        pkg_hashes_cache,
        task_pkg_hashes,
        packages,
        count_list,
        force_load,
        *args,
        **kwargs,
    ) -> None:
        self.conn = conn
        self.girar = girar
        self.logger = logger
        self.cache = pkg_hashes_cache
        self.pkg_hashes = task_pkg_hashes
        self.packages = packages
        self.count_list = count_list
        self.count = 0
        self.lock = threading.Lock()
        self.force = force_load
        super().__init__(*args, **kwargs)

    def _insert_package(self, pkg, srpm_hash, is_srpm):
        st = time.time()
        kw = {}
        hdr = self.girar.get_header(pkg)
        sha1 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_SHA1HEADER]))
        hashes = {"sha1": sha1, "mmh": mmhash(sha1)}
        pkg_name = Path(pkg).name

        if self.pkg_hashes[pkg_name]["md5"]:
            hashes["md5"] = self.pkg_hashes[pkg_name]["md5"]
        else:
            self.logger.debug(f"calculate MD5 for {pkg_name} file")
            hashes["md5"] = md5_from_file(self.girar.get_file_path(pkg), as_bytes=True)

        if self.pkg_hashes[pkg_name]["sha256"]:
            hashes["sha256"] = self.pkg_hashes[pkg_name]["sha256"]
        else:
            self.logger.debug(f"calculate SHA256 for {pkg_name} file")
            hashes["sha256"] = sha256_from_file(
                self.girar.get_file_path(pkg), as_bytes=True
            )

        kw["pkg_hash"] = hashes["mmh"]
        kw["pkg_filename"] = pkg_name
        kw["pkg_filesize"] = self.girar.get_file_size(pkg)
        if is_srpm:
            kw["pkg_sourcerpm"] = pkg_name
            kw["pkg_srcrpm_hash"] = hashes["mmh"]
        else:
            kw["pkg_srcrpm_hash"] = srpm_hash

        if self.force or not extract.check_package_in_cache(self.cache, hashes["mmh"]):
            extract.insert_package(self.conn, hdr, self.girar.get_file_path(pkg), **kw)
            extract.insert_pkg_hash_single(self.conn, hashes)
            self.cache.add(hashes["mmh"])
            self.count += 1
            self.logger.debug(
                f"package loaded in {(time.time() - st):.3f} seconds : {hashes['sha1'].hex()} : {kw['pkg_filename']}"
            )
        else:
            self.logger.debug(
                f"package already loaded : {hashes['sha1'].hex()} : {kw['pkg_filename']}"
            )

        return hashes["mmh"]

    def run(self):
        self.logger.debug(f"thread {self.ident} start")
        for pkg in self.packages:
            try:
                self._insert_package(pkg, 0, is_srpm=False)
            except Exception as error:
                self.logger.error(error, exc_info=True)
                self.exc = error
                self.exc_message = f"Exception in thread {self.name} for package {pkg}"
                self.exc_traceback = traceback.format_exc()
                break
        self.logger.debug(f"thread {self.ident} stop")
        self.count_list.append(self.count)


def package_load_worker_pool(
    args,
    conn,
    girar,
    logger,
    task_pkg_hashes,
    packages_,
    num_of_workers=None,
    loaded_from="",
):
    st = time.time()
    workers = []
    pkg_count = []
    connections = []
    packages = LockedIterator((pkg for pkg in packages_))

    pkg_hashes_cache = init_cache(conn, packages_)

    if num_of_workers:
        args.workers = num_of_workers

    for i in range(args.workers):
        conn = get_client(args)
        connections.append(conn)
        worker = PackageLoaderWorker(
            conn,
            girar,
            logger,
            pkg_hashes_cache,
            task_pkg_hashes,
            packages,
            pkg_count,
            args.force,
        )
        worker.start()
        workers.append(worker)

    for w in workers:
        try:
            w.join()
        except RaisingThreadError as e:
            logger.error(e.message)
            # print(e.traceback)
            raise e

    for c in connections:
        if c is not None:
            c.disconnect()
    if sum(pkg_count):
        logger.info(
            f"{sum(pkg_count)} packages loaded in {(time.time() - st):.3f} seconds from {loaded_from}"
        )


class Task:
    def __init__(self, conn, girar, logger, task, args):
        self.girar = girar
        self.conn = conn
        self.logger = logger
        self.task = task
        self.args = args
        # self.cache = extract.init_cache(self.conn)
        self.approvals = []

    def _save_task(self):
        # 1 - proceed with TaskStates
        self.task["task_state"]["task_eventlog_hash"] = []
        # 1.1 - save event logs hashes
        for _, _, log_hash, _ in [_ for _ in self.task["logs"] if _[0] == "events"]:
            self.task["task_state"]["task_eventlog_hash"].append(log_hash)
        # 1.2 - save current task state
        self.conn.execute(
            "INSERT INTO TaskStates_buffer (*) VALUES", [self.task["task_state"]]
        )
        # 2 - proceed with TaskApprovals
        # 2.1 - collect task approvals from DB
        TaskInfo = namedtuple(
            "TaskInfo",
            (
                "task_id",
                "subtask_id",
                "tapp_type",
                "tapp_revoked",
                "tapp_date",
                "tapp_name",
                "tapp_message",
            ),
        )
        res = self.conn.execute(
            """SELECT argMax(tuple(*), ts) FROM TaskApprovals
            WHERE task_id = %(task_id)s GROUP BY (subtask_id, tapp_name)""",
            {"task_id": self.task["task_state"]["task_id"]},
        )
        tapps_from_db = [TaskInfo(*_[0])._asdict() for _ in res]
        for tapp in tapps_from_db:
            tapp["tapp_date"] = cvt_datetime_local_to_utc(tapp["tapp_date"])

        tapps_from_fs = deepcopy(self.task['task_approvals'])

        # 2.2 - collect previous approvals that are not rewoked
        tapps = []
        for tapp in deepcopy(tapps_from_db):
            if tapp["tapp_revoked"] == 0:
                del tapp["tapp_revoked"]
                tapps.append(tapp)
        # 2.3 - find rewoked by compare DB and actual task approvals
        tapps_revoked = []
        for tapp in tapps:
            if tapp not in self.task["task_approvals"]:
                tapp["tapp_revoked"] = 1
                tapp["tapp_date"] = cvt_datetime_local_to_utc(datetime.datetime.now())
                tapps_revoked.append(tapp)
        # 2.4 - set 'tapp_rewoked' flag for new and not revoked ones
        for tapp in tapps_from_fs:
            if "tapp_revoked" not in tapp:
                tapp["tapp_revoked"] = 0
        tapps_from_fs += tapps_revoked
        # 2.5 - remove task approvals that already in database
        new_task_approvals = []
        for tapp in tapps_from_fs:
            if tapp not in tapps_from_db:
                new_task_approvals.append(tapp)
        self.task["task_approvals"] = new_task_approvals
        # 2.6 - load new approvals state to DB
        if self.task["task_approvals"]:
            self.conn.execute(
                "INSERT INTO TaskApprovals (*) VALUES", self.task["task_approvals"]
            )
        # 3 - proceed with Tasks
        if self.task["tasks"]:
            self.conn.execute("INSERT INTO Tasks_buffer (*) VALUES", self.task["tasks"])
        # 4 - load all logs
        if self.task["logs"]:
            log_load_worker_pool(
                self.args,
                self.girar,
                self.logger,
                self.task["logs"],
                num_of_workers=None,
            )
        # 5 - proceed with TaskIterations
        if self.task["task_iterations"]:
            titer_load_worker_pool(
                self.args,
                self.conn,
                self.girar,
                self.logger,
                self.task["pkg_hashes"],
                self.task["logs"],
                self.task["task_iterations"],
                num_of_workers=None,
            )
        # 6 - load arepo packages
        # for pkg in self.task['arepo']:
        #     self._insert_package(pkg, 0, is_srpm=False)
        if self.task["arepo"]:
            package_load_worker_pool(
                self.args,
                self.conn,
                self.girar,
                self.logger,
                self.task["pkg_hashes"],
                self.task["arepo"],
                num_of_workers=None,
                loaded_from="'/arepo'",
            )
        # 7 - load plan
        # 7.1 - load plan package add and delete
        payload = []
        for arch in self.task["plan"]["pkg_add"].keys():
            for k, v in self.task["plan"]["pkg_add"][arch].items():
                payload.append(
                    {
                        "tplan_hash": self.task["plan"]["hashes"][arch],
                        "tplan_action": "add",
                        "tplan_pkg_name": v[0],
                        "tplan_pkg_evr": v[1],
                        "tplan_bin_file": k,
                        "tplan_src_file": v[2],
                        "tplan_arch": v[3],
                        "tplan_comp": v[4],
                        "tplan_subtask": v[5],
                    }
                )
        for arch in self.task["plan"]["pkg_del"].keys():
            for k, v in self.task["plan"]["pkg_del"][arch].items():
                payload.append(
                    {
                        "tplan_hash": self.task["plan"]["hashes"][arch],
                        "tplan_action": "delete",
                        "tplan_pkg_name": v[0],
                        "tplan_pkg_evr": v[1],
                        "tplan_bin_file": k,
                        "tplan_src_file": v[2],
                        "tplan_arch": v[3],
                        "tplan_comp": v[4],
                        "tplan_subtask": v[5],
                    }
                )
        if payload:
            self.conn.execute("""INSERT INTO TaskPlanPackages (*) VALUES""", payload)
        # 7.2 - load plan package hashes add and delete
        payload = []
        for arch in self.task["plan"]["hash_add"].keys():
            for k, v in self.task["plan"]["hash_add"][arch].items():
                payload.append(
                    {
                        "tplan_hash": self.task["plan"]["hashes"][arch],
                        "tplan_action": "add",
                        "tplan_sha256": v,
                    }
                )
        for arch in self.task["plan"]["hash_del"].keys():
            for k, v in self.task["plan"]["hash_del"][arch].items():
                payload.append(
                    {
                        "tplan_hash": self.task["plan"]["hashes"][arch],
                        "tplan_action": "delete",
                        "tplan_sha256": v,
                    }
                )
        if payload:
            self.conn.execute("""INSERT INTO TaskPlanPkgHash (*) VALUES""", payload)

    def _update_dependencies_table(self):
        sql = """
INSERT INTO Depends SELECT * FROM
(
    WITH
    unmet_file_depends AS
    (
        SELECT DISTINCT dp_name
        FROM Depends
        WHERE dp_type = 'require' AND dp_name NOT IN
        (
            SELECT dp_name
            FROM Depends
            WHERE dp_type = 'provide'
        )
            AND dp_name NOT LIKE 'rpmlib%'
    ),
    file_names_hash AS
    (
        SELECT DISTINCT
            fn_hash,
            fn_name
        FROM FileNames
        WHERE fn_name IN (SELECT * FROM unmet_file_depends)
    )
    SELECT
        pkg_hash,
        UDF.fn_name AS dp_name,
        '' AS dp_version,
        0  AS dp_flag,
        'provide' AS dp_type
    FROM Files
    INNER JOIN
    (
        SELECT * FROM file_names_hash
    ) AS UDF ON UDF.fn_hash = Files.file_hashname
)
"""
        self.logger.info("Updating Depends table for missing file riquire dependencies")
        self.conn.execute(sql)
        self.logger.debug(f"SQL request elapsed {self.conn.last_query.elapsed:.3f} seconds")

    def _flush_buffer_tables(self):
        """Force flush bufeer tables using OPTIMIZE TABLE SQL requests."""
        buffer_tables = (
            "Files_buffer",
            "Depends_buffer",
            "Changelog_buffer",
            "Packages_buffer",
            "TaskIterations_buffer",
            "Tasks_buffer",
            "TaskStates_buffer",
            "Specfiles_buffer",
        )
        for buffer in buffer_tables:
            self.conn.execute(f"OPTIMIZE TABLE {buffer}")

    def flush(self):
        self._flush_buffer_tables()

    def save(self):
        self._save_task()

    def update_depends(self):
        self._update_dependencies_table()


class Girar:
    def __init__(self, url):
        self.url = url
        self.ts = rpm.TransactionSet()

    def _get_content(self, url, status=False):
        try:
            r = urllib.request.urlopen(url)
        except urllib.error.URLError as e:
            log.debug("{0} - {1}".format(e, url))
            if status:
                return False
            return None
        except Exception as e:
            log.error("{0} - {1}".format(e, url))
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
    def __init__(self, path):
        self.path = Path(path)
        self.ts = rpm.TransactionSet()

    def _get_content(self, path, status=False):
        r = None
        if status:
            if Path(path).exists():
                return True
            else:
                return False
        try:
            r = Path(path).read_bytes()
        except IsADirectoryError:
            # return directory listing
            return [_ for _ in Path(path).iterdir()]
        except FileNotFoundError as e:
            log.debug(f"{e} - {path}")
            return None
        except Exception as e:
            log.error(f"{e} - {path}")
            return None
        return r

    def get(self, path):
        p = Path.joinpath(self.path, path)
        r = self._get_content(p, status=False)
        return cvt(r)

    def check(self):
        return self._get_content(self.path, status=True)

    def check_file(self, path):
        p = Path.joinpath(self.path, path)
        return self._get_content(p, status=True)

    def get_bytes(self, path):
        p = Path.joinpath(self.path, path)
        r = self._get_content(p, status=False)
        return r

    def get_file_mtime(self, path):
        p = Path.joinpath(self.path, path)
        try:
            mtime = p.stat().st_mtime
        except FileNotFoundError:
            return None
        return cvt_ts_to_datetime(mtime, use_local_tz=False)

    def get_file_size(self, path):
        p = Path.joinpath(self.path, path)
        try:
            file_size = p.stat().st_size
        except FileNotFoundError:
            return 0
        return file_size

    def get_header(self, path):
        log.debug(f"reading header for {path}")
        return extract.get_header(self.ts, str(Path.joinpath(self.path, path)))

    def get_file_path(self, path):
        return Path.joinpath(self.path, path)

    def file_exists_and_not_empty(self, path):
        p = Path.joinpath(self.path, path)
        if p.is_file() and p.stat().st_size > 0:
            return True
        else:
            return False

    def get_symlink_target(self, path, name_only=False):
        symlink = Path.joinpath(self.path, path)
        if symlink.is_symlink():
            if name_only:
                return str(symlink.resolve().name)
            else:
                return str(symlink.resolve())
        else:
            return None

    def parse_approval_file(self, path):
        p = Path.joinpath(self.path, path)
        r = self._get_content(p, status=False)
        n = d = m = None
        if r:
            r = cvt(r)
            try:
                d, *m = [_ for _ in r.split("\n") if len(_) > 0]
                d, n = [_.strip() for _ in d.split("::") if len(_) > 0]
                n = n.split(" ")[-1]
                d = datetime.datetime.strptime(d, "%Y-%b-%d %H:%M:%S")
                d = set_datetime_timezone_to_utc(d)
                m = "\n".join((_ for _ in m))
                return (n, d, m)
            except Exception as e:
                log.error(
                    f"File parsing failed with error {e} for '{path}' contains '{r}'"
                )
        return None


def init_task_structure_from_task(girar):
    """Loads all available contents from task to dictionary

    Args:
        girar (class): Girar class instance initialized with exact task

    Returns:
        dict: parsed task structure with contents
    """
    task = {
        "tasks": [],
        "task_state": {},
        "task_approvals": [],
        "task_iterations": [],
        "arepo": [],
        "logs": [],
        "plan": {},
        "pkg_hashes": defaultdict(lambda: defaultdict(lambda: None, key=None)),
    }
    # parse '/task' and '/info.json' for 'TaskStates'
    if girar.check_file("task/state"):
        task["task_state"]["task_changed"] = girar.get_file_mtime("task/state")
        t = girar.get_file_mtime("info.json")
        if t and t > task["task_state"]["task_changed"]:
            task["task_state"]["task_changed"] = t
    else:
        # skip tasks with uncertain state for God sake
        return task
    task["task_state"]["task_id"] = int(girar.get_file_path("").name)
    t = girar.get("task/state")
    task["task_state"]["task_state"] = t.strip() if t else ""
    t = girar.get("task/run")
    task["task_state"]["task_runby"] = t.strip() if t else ""
    t = girar.get("task/depends")
    task["task_state"]["task_depends"] = (
        [int(_) for _ in t.split("\n") if len(_) > 0] if t else []
    )
    t = girar.get("task/try")
    task["task_state"]["task_try"] = int(t.strip()) if t else 0
    t = girar.get("task/iter")
    task["task_state"]["task_iter"] = int(t.strip()) if t else 0
    task["task_state"]["task_testonly"] = 1 if girar.check_file("task/test-only") else 0
    task["task_state"]["task_failearly"] = (
        1 if girar.check_file("task/fail-early") else 0
    )
    t = val_from_json_str(girar.get("info.json"), "shared")
    task["task_state"]["task_shared"] = 1 if t else 0
    t = girar.get("task/message")
    task["task_state"]["task_message"] = t.strip() if t else ""
    t = girar.get("task/version")
    task["task_state"]["task_version"] = t.strip() if t else ""
    t = girar.get_symlink_target("build/repo/prev", name_only=True)
    task["task_state"]["task_prev"] = int(t.strip()) if t else 0
    # parse '/plan' and '/build/repo' for diff lists and hashes
    # check if task '/plan' is up to date. Workaround for bug #40728
    task["plan"]["pkg_add"] = {}
    task["plan"]["pkg_del"] = {}
    task["plan"]["hash_add"] = {}
    task["plan"]["hash_del"] = {}
    load_plan = False
    if task["task_state"]["task_try"] != 0 and task["task_state"]["task_iter"] != 0:
        task_tryiter_time = max(
            girar.get_file_mtime("task/try"), girar.get_file_mtime("task/iter")
        )
        task_plan_time = girar.get_file_mtime("plan")
        if task_plan_time > task_tryiter_time:
            load_plan = True
    # always load plan if task in 'DONE' state
    if task["task_state"]["task_state"] == "DONE":
        load_plan = True
    if load_plan:
        # -1 - get binary packages add and delete from plan
        t = girar.get("plan/add-bin")
        pkgadd = {}
        if t:
            pkgadd = {}
            for f in (_ for _ in t.split("\n") if len(_) > 0):
                f = f.split("\t")
                if len(f) >= 7:
                    # new tasksk with component in plan
                    pkgadd[f[3]] = (f[2], f[6], int(f[5]))
                else:
                    # old tasksk without component in plan
                    pkgadd[f[3]] = (f[2], "", int(f[5]))

        t = girar.get("plan/rm-bin")
        pkgdel = {}
        if t:
            for f in (_ for _ in t.split("\n") if len(_) > 0):
                f = f.split("\t")
                if len(f) >= 5:
                    # new tasksk with component in plan
                    pkgdel[f[3]] = (f[2], f[4], 0)
                else:
                    # old tasksk without component in plan
                    pkgdel[f[3]] = (f[2], "", 0)

        # 0 - get packages list diffs
        for pkgdiff in (_ for _ in girar.get_file_path("plan").glob("*.list.diff")):
            if pkgdiff.name == "src.list.diff":
                p_add, p_del = parse_pkglist_diff(pkgdiff, is_src_list=True)
            else:
                p_add, p_del = parse_pkglist_diff(pkgdiff, is_src_list=False)
            for p in p_add:
                p_info = {
                    p.file: (p.name, p.evr, p.srpm, *pkgadd.get(p.file, ("", "", 0)))
                }
                if p.arch not in task["plan"]["pkg_add"]:
                    task["plan"]["pkg_add"][p.arch] = {}
                task["plan"]["pkg_add"][p.arch].update(p_info)
            for p in p_del:
                p_info = {
                    p.file: (p.name, p.evr, p.srpm, *pkgdel.get(p.file, ("", "", 0)))
                }
                if p.arch not in task["plan"]["pkg_del"]:
                    task["plan"]["pkg_del"][p.arch] = {}
                task["plan"]["pkg_del"][p.arch].update(p_info)
        # 1 - get SHA256 hashes from '/plan/*.hash.diff'
        for hashdiff in (_ for _ in girar.get_file_path("plan").glob("*.hash.diff")):
            h_add, h_del = parse_hash_diff(hashdiff)
            h_arch = hashdiff.name.split(".")[0]
            task["plan"]["hash_add"][h_arch] = h_add
            task["plan"]["hash_del"][h_arch] = h_del
            for k, v in h_add.items():
                task["pkg_hashes"][k]["sha256"] = v
    # 2 - get MD5 hashes from '/build/repo/%arch%/base/pkglist.task.xz'
    for pkglist in (
        _ for _ in girar.get_file_path("build/repo").glob("*/base/pkglist.task.xz")
    ):
        hdrs = extract.read_headers_from_xz_pkglist(pkglist)
        for hdr in hdrs:
            pkg_name = cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYFILENAME])
            pkg_md5 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYMD5]))
            # workaround for duplicated noarch packages with wrong MD5 from pkglist.task.xz
            if task["pkg_hashes"][pkg_name]["md5"]:
                if task["pkg_hashes"][pkg_name]["md5"] != pkg_md5:
                    log.debug(
                        f"Found mismatching MD5 from APT hash for {pkg_name}. Calculating MD5 from file"
                    )
                    t = [
                        _
                        for _ in girar.get_file_path("build/repo").glob(
                            f"*/RPMS.task/{pkg_name}"
                        )
                    ]
                    if t:
                        task["pkg_hashes"][pkg_name]["md5"] = md5_from_file(
                            t[0], as_bytes=True
                        )
                    else:
                        log.error(f"Failed to calculate MD5 for {pkg_name} from file")
                else:
                    continue
            else:
                task["pkg_hashes"][pkg_name]["md5"] = pkg_md5
    # 3 - set hashes for TaskPlan* tables
    p_arch = {_ for _ in task["plan"]["pkg_add"].keys()}
    p_arch.update({_ for _ in task["plan"]["pkg_del"].keys()})
    p_arch.update({_ for _ in task["plan"]["hash_add"].keys()})
    p_arch.update({_ for _ in task["plan"]["hash_del"].keys()})
    task["plan"]["hashes"] = {}
    for arch in p_arch:
        plan_hash = (
            ""
            + str(task["task_state"]["task_id"])
            + str(task["task_state"]["task_try"])
            + str(task["task_state"]["task_iter"])
            + arch
        )
        task["plan"]["hashes"][arch] = mmhash(plan_hash)
    # parse '/acl' for 'TaskApprovals'
    # 0 - iterate through 'acl/approved'
    for subtask in (
        _.name
        for _ in girar.get_file_path("acl/disapproved").glob("[0-7]*")
        if _.is_dir()
    ):
        subtask_dir = "/".join(("acl/approved", subtask))
        for approver in (_.name for _ in girar.get(subtask_dir) if _.is_file()):
            t = girar.parse_approval_file("/".join((subtask_dir, approver)))
            if t:
                approval = {
                    "task_id": task["task_state"]["task_id"],
                    "subtask_id": int(subtask),
                    "tapp_type": "approve",
                    # 'tapp_revoked': None,
                    "tapp_name": t[0],
                    "tapp_date": t[1],
                    "tapp_message": t[2],
                }
                task["task_approvals"].append(approval)
    # 1 - iterate through 'acl/dsiapproved'
    for subtask in (
        _.name
        for _ in girar.get_file_path("acl/disapproved").glob("[0-7]*")
        if _.is_dir()
    ):
        subtask_dir = "/".join(("acl/disapproved", subtask))
        for approver in (_.name for _ in girar.get(subtask_dir) if _.is_file()):
            t = girar.parse_approval_file("/".join((subtask_dir, approver)))
            if t:
                approval = {
                    "task_id": task["task_state"]["task_id"],
                    "subtask_id": int(subtask),
                    "tapp_type": "disapprove",
                    # 'tapp_revoked': None,
                    "tapp_name": t[0],
                    "tapp_date": t[1],
                    "tapp_message": t[2],
                }
                task["task_approvals"].append(approval)
    # parse '/gears' for 'Tasks'
    for subtask in (
        _.name for _ in girar.get_file_path("gears").glob("[0-7]*") if _.is_dir()
    ):
        subtask_dir = "/".join(("gears", subtask))
        files = set((_.name for _ in girar.get(subtask_dir)))
        sid = girar.get("/".join((subtask_dir, "sid")))

        subtask_dict = {
            "task_id": task["task_state"]["task_id"],
            "subtask_id": int(subtask),
            "task_repo": girar.get("task/repo").strip(),
            "task_owner": girar.get("task/owner").strip(),
            "task_changed": task["task_state"]["task_changed"],
            "subtask_changed": None,
            "subtask_userid": girar.get("/".join((subtask_dir, "userid"))).strip(),
            "subtask_sid": sid.split(":")[1].strip() if sid else "",
            "subtask_dir": "",
            "subtask_package": "",
            "subtask_type": sid.split(":")[0] if sid else "",
            "subtask_pkg_from": "",
            "subtask_tag_author": "",
            "subtask_tag_id": "",
            "subtask_tag_name": "",
            "subtask_srpm": "",
            "subtask_srpm_name": "",
            "subtask_srpm_evr": "",
        }

        if girar.check_file("/".join((subtask_dir, "userid"))):
            subtask_dict["subtask_changed"] = girar.get_file_mtime(
                "/".join((subtask_dir, "userid"))
            )
        else:
            subtask_dict["subtask_changed"] = girar.get_file_mtime(subtask_dir)

        if "dir" not in files and "srpm" not in files and "package" not in files:
            # deleted subtask
            subtask_dict["subtask_deleted"] = 1
            subtask_dict["subtask_type"] = "unknown"
        else:
            subtask_dict["subtask_deleted"] = 0
            # logic from girar-task-run check_copy_del()
            if girar.file_exists_and_not_empty(
                "/".join((subtask_dir, "package"))
            ) and not girar.file_exists_and_not_empty("/".join((subtask_dir, "dir"))):
                if girar.file_exists_and_not_empty(
                    "/".join((subtask_dir, "copy_repo"))
                ):
                    t = girar.get("/".join((subtask_dir, "copy_repo")))
                    subtask_dict["subtask_type"] = "copy"
                    subtask_dict["subtask_pkg_from"] = t.strip()
                else:
                    subtask_dict["subtask_type"] = "delete"

            if girar.check_file("/".join((subtask_dir, "rebuild"))):
                t = girar.get("/".join((subtask_dir, "rebuild")))
                subtask_dict["subtask_type"] = "rebuild"
                subtask_dict["subtask_pkg_from"] = t.strip()
            # changed in girar @ e74d8067009d
            if girar.check_file("/".join((subtask_dir, "rebuild_from"))):
                t = girar.get("/".join((subtask_dir, "rebuild_from")))
                subtask_dict["subtask_type"] = "rebuild"
                subtask_dict["subtask_pkg_from"] = t.strip()
            if subtask_dict["subtask_type"] == "":
                subtask_dict["subtask_type"] = "unknown"
            t = girar.get("/".join((subtask_dir, "dir")))
            subtask_dict["subtask_dir"] = t.strip() if t else ""
            t = girar.get("/".join((subtask_dir, "package")))
            subtask_dict["subtask_package"] = t.strip() if t else ""
            t = girar.get("/".join((subtask_dir, "tag_author")))
            subtask_dict["subtask_tag_author"] = t.strip() if t else ""
            t = girar.get("/".join((subtask_dir, "tag_id")))
            subtask_dict["subtask_tag_id"] = t.strip() if t else ""
            t = girar.get("/".join((subtask_dir, "tag_name")))
            subtask_dict["subtask_tag_name"] = t.strip() if t else ""
            t = girar.get("/".join((subtask_dir, "srpm")))
            subtask_dict["subtask_srpm"] = t.strip() if t else ""
            t = girar.get("/".join((subtask_dir, "nevr")))
            if t:
                subtask_dict["subtask_srpm_name"] = t.split("\t")[0].strip()
                subtask_dict["subtask_srpm_evr"] = t.split("\t")[1].strip()
        task["tasks"].append(subtask_dict)
    # parse '/build' for 'TaskIterations'
    # 0 - get src and packages from plan
    src_pkgs = {}
    bin_pkgs = defaultdict(lambda: defaultdict(list))
    t = girar.get("plan/add-src")
    if t:
        for *_, pkg, n in [_.split("\t") for _ in t.split("\n") if len(_) > 0]:
            src_pkgs[n] = pkg
    t = girar.get("plan/add-bin")
    if t:
        for _, _, arch, _, pkg, n, *_ in [
            _.split("\t") for _ in t.split("\n") if len(_) > 0
        ]:
            bin_pkgs[n][arch].append(pkg)
    # 1 - get contents from /build/%subtask_id%/%arch%
    for subtask in (
        _.name for _ in girar.get_file_path("build").glob("[0-7]*") if _.is_dir()
    ):
        subtask_dir = "/".join(("build", subtask))
        # follow order of architectures from ARCHS list to prefer
        # source package from 'x86_64' and 'i586' architectures if there is no plan
        archs_fs = set((x.name for x in girar.get(subtask_dir) if x.is_dir()))
        archs = [x for x in ('x86_64', 'i586') if x in archs_fs]
        archs += [x for x in archs_fs if x not in archs]
        for arch in archs:
            arch_dir = "/".join((subtask_dir, arch))
            build_dict = {
                "task_id": task["task_state"]["task_id"],
                "task_changed": task["task_state"]["task_changed"],
                "subtask_id": int(subtask),
                "subtask_arch": arch,
                "titer_ts": None,
                "titer_status": None,
                "task_try": None,
                "task_iter": None,
                "titer_srpm": None,  # 'titer_srcrpm_hash'
                "titer_rpms": [],  # 'titer_pkgs_hash'
                "titer_chroot_base": [],
                "titer_chroot_br": [],
            }
            if girar.check_file("/".join((arch_dir, "status"))):
                t = girar.get_file_mtime("/".join((arch_dir, "status")))
                tt = girar.get("/".join((arch_dir, "status")))
                build_dict["titer_status"] = tt.strip() if tt else "failed"
            else:
                t = girar.get_file_mtime(arch_dir)
                build_dict["titer_status"] = "failed"
            build_dict["titer_ts"] = t
            build_dict["task_try"] = task["task_state"]["task_try"]
            build_dict["task_iter"] = task["task_state"]["task_iter"]
            # read chroots
            t = girar.get("/".join((arch_dir, "chroot_base")))
            if t:
                for pkg in (
                    _.split("\t")[-1].strip() for _ in t.split("\n") if len(_) > 0
                ):
                    build_dict["titer_chroot_base"].append(mmhash(bytes.fromhex(pkg)))
            t = girar.get("/".join((arch_dir, "chroot_BR")))
            if t:
                for pkg in (
                    _.split("\t")[-1].strip() for _ in t.split("\n") if len(_) > 0
                ):
                    build_dict["titer_chroot_br"].append(mmhash(bytes.fromhex(pkg)))
            # get src and bin packages
            t = girar.get("/".join((arch_dir, "srpm")))
            if t and len(t) > 0:
                build_dict["titer_status"] = "built"
                # skip srpm if got it from 'plan/add-src'
                # TODO: handle particular srpm package loading somehow if plan exists
                if subtask not in src_pkgs:
                    src_pkgs[subtask] = "/".join((arch_dir, "srpm", t[0].name))
            if subtask in src_pkgs:
                build_dict["titer_srpm"] = src_pkgs[subtask]

            t = girar.get("/".join((arch_dir, "rpms")))
            if t and len(t) > 0:
                build_dict["titer_status"] = "built"
                bin_pkgs[subtask][arch] = []
                for brpm in t:
                    bin_pkgs[subtask][arch].append(
                        "/".join((arch_dir, "rpms", brpm.name))
                    )

            if subtask in bin_pkgs and arch in bin_pkgs[subtask]:
                build_dict["titer_rpms"] = [_ for _ in bin_pkgs[subtask][arch]]
            task["task_iterations"].append(build_dict)
            # save build logs
            for log_file in ("log", "srpm.log"):
                if girar.file_exists_and_not_empty("/".join((arch_dir, log_file))):
                    log_hash = (
                        ""
                        + str(build_dict["task_id"])
                        + str(build_dict["subtask_id"])
                        + str(build_dict["task_try"])
                        + str(build_dict["task_iter"])
                        + build_dict["subtask_arch"]
                    )
                    if log_file == "log":
                        log_hash = "build" + log_hash
                        task["logs"].append(
                            (
                                "build",
                                "/".join((arch_dir, log_file)),
                                mmhash(log_hash),
                                log_hash,
                            )
                        )
                    else:
                        log_hash = "srpm" + log_hash
                        task["logs"].append(
                            (
                                "srpm",
                                "/".join((arch_dir, log_file)),
                                mmhash(log_hash),
                                log_hash,
                            )
                        )
    # generate task iterations for subtask with 'delete' action
    build_subtasks = {_["subtask_id"] for _ in task["task_iterations"]}
    for t in task["tasks"]:
        if t["subtask_deleted"] == 0 and t["subtask_type"] == "delete":
            if t["subtask_id"] not in build_subtasks:
                # create stub task iteration
                build_dict = {
                    "task_id": task["task_state"]["task_id"],
                    "task_changed": task["task_state"]["task_changed"],
                    "subtask_id": t["subtask_id"],
                    "subtask_arch": "x86_64",
                    "titer_ts": girar.get_file_mtime("build"),
                    "titer_status": "deleted",
                    "task_try": task["task_state"]["task_try"],
                    "task_iter": task["task_state"]["task_iter"],
                    "titer_srpm": None,
                    "titer_rpms": [],
                    "titer_chroot_base": [],
                    "titer_chroot_br": [],
                }
                task["task_iterations"].append(build_dict)
    # parse '/arepo' for packages
    t = girar.get("arepo/x86_64-i586/rpms")
    for pkg in (_.name for _ in t if t and _.suffix == ".rpm"):
        task["arepo"].append(f"arepo/x86_64-i586/rpms/{pkg}")
    # parse '/logs' for event logs
    for log_file in (_.name for _ in girar.get_file_path("logs").glob("events.*.log")):
        log_hash = (
            "events"
            + str(task["task_state"]["task_id"])
            + log_file.split(".")[1]
            + log_file.split(".")[2]
        )
        task["logs"].append(
            ("events", "/".join(("logs", log_file)), mmhash(log_hash), log_hash)
        )

    return task


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", type=str, help="git.altlinux task url")
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database password")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument("-w", "--workers", type=int, help="Workers count (default: 4)")
    parser.add_argument(
        "-D",
        "--dumpjson",
        action="store_true",
        help="Dump parsed task structure to JSON file",
    )
    parser.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="Force to load packages from task to database",
    )
    parser.add_argument(
        "-f",
        "--flush-buffers",
        action="store_true",
        help="Force to flush buffer tables after task loaded",
    )
    args = parser.parse_args()
    args.workers = args.workers or 10
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        if cfg.has_section("DATABASE"):
            section_db = cfg["DATABASE"]
            args.dbname = args.dbname or section_db.get("dbname", "default")
            args.host = args.host or section_db.get("host", "localhost")
            args.port = args.port or section_db.get("port", None)
            args.user = args.user or section_db.get("user", "default")
            args.password = args.password or section_db.get("password", "")
    else:
        args.dbname = args.dbname or "default"
        args.host = args.host or "localhost"
        args.port = args.port or None
        args.user = args.user or "default"
        args.password = args.password or ""
    return args


def load(args, conn):
    # girar = Girar(args.url)
    girar = TaskFromFS(args.url)
    if girar.check():
        ts = time.time()
        log.info(f"reading task structure for {args.url}")
        task_struct = init_task_structure_from_task(girar)
        log.info(f"task structure loaded in {(time.time() - ts):.3f} seconds")
        if args.dumpjson:
            p = Path.joinpath(Path.cwd(), "JSON")
            p.mkdir(exist_ok=True)
            Path.joinpath(
                p,
                f"dump-{str(task_struct['task_state']['task_id'])}-{datetime.date.today().strftime('%Y-%m-%d')}.json",
            ).write_text(json.dumps(task_struct, indent=2, sort_keys=True, default=str))
        task = Task(conn, girar, log, task_struct, args)
        log.info(
            f"loading task {task_struct['task_state']['task_id']} to database {args.dbname}"
        )
        task.save()
        if args.flush_buffers:
            log.info("Flushing buffer tables")
            task.flush()
        # update Depends table
        task.update_depends()
        ts = time.time() - ts
        log.info(
            f"task {task_struct['task_state']['task_id']} loaded in {ts:.3f} seconds"
        )
    else:
        raise ValueError("task not found: {0}".format(args.url))


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    if args.url.endswith("/"):
        args.url = args.url[:-1]
    logger = get_logger(NAME, tag=(args.url.split("/")[-1]))
    logger.setLevel(logging.INFO)
    logger.info(f"run with args: {args}")
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


if __name__ == "__main__":
    main()
