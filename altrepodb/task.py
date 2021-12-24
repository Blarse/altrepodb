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

import re
import time
import datetime
import threading
import traceback
from pathlib import Path
from copy import deepcopy
from collections import defaultdict, namedtuple
from dataclasses import asdict
from typing import Iterable, Any, Iterator, Union, Generator

from altrpm import rpm, readHeaderListFromXZFile
from .repo import PackageHandler
from .logger import LoggerProtocol
from .utils import (
    cvt,
    mmhash,
    dump_to_json,
    snowflake_id_pkg,
    md5_from_file,
    sha256_from_file,
    blake2b_from_file,
    val_from_json_str,
    cvt_ts_to_datetime,
    check_package_in_cache,
    cvt_datetime_local_to_utc,
    set_datetime_timezone_to_utc,
)
from .base import (
    DEFAULT_LOGGER,
    _StringOrPath,
    LockedIterator,
    GeneratorWrapper,
    PkgHash,
    PkgInfo,
    RaisingTread,
    Task,
    TaskLog,
    TaskPlan,
    TaskState,
    TaskSubtask,
    TaskApproval,
    TaskIteration,
    TaskProcessorConfig,
)
from .database import DatabaseClient
from .exceptions import (
    RaisingThreadError,
    TaskLoaderParserError,
    TaskLoaderProcessingError,
    TaskLoaderInvalidPathError,
)


NAME = "task"

# Named tuples
TaskPlanDiffPkgInfo = namedtuple(
    "TaskPlanDiffPkgInfo", ["name", "evr", "file", "srpm", "arch"]
)
TaskPlanAddRmPkgInfo = namedtuple(
    "TaskPlanAddRmPkgInfo",
    ["name", "evr", "arch", "file", "path", "subtask_id", "comp"],
)


def init_cache(conn: DatabaseClient, packages: Iterable[str], logger: LoggerProtocol):
    result = conn.execute(
        """CREATE TEMPORARY TABLE IF NOT EXISTS PkgFNameTmp (pkg_filename String)"""
    )
    payload = []
    for pkg_name in [x.split("/")[-1] for x in packages]:
        payload.append({"pkg_filename": pkg_name})

    result = conn.execute("INSERT INTO PkgFNameTmp (*) VALUES", payload)

    logger.debug(f"Inserted {len(payload)} 'pkg_filename's into PkgFNameTmp")

    result = conn.execute(
        """SELECT pkg_hash
           FROM Packages_buffer
           WHERE pkg_filename IN
             (SELECT * FROM PkgFNameTmp)"""
    )

    return {i[0] for i in result}


def task_as_dict(task: Task) -> dict:
    """Dumps Task class instance to dictionary representation."""

    return {
        "id": task.id,
        "arepo": task.arepo,
        "plan": asdict(task.plan),
        "state": asdict(task.state),
        "logs": [asdict(x) for x in task.logs],
        "subtasks": [asdict(x) for x in task.subtasks],
        "approvals": [asdict(x) for x in task.approvals],
        "iterations": [asdict(x) for x in task.iterations],
        "pkg_hashes": {k: asdict(v) for k, v in dict(task.pkg_hashes).items()}
    }


class TaskFromFileSystem:
    """Provides functions to read task's elements from filesystem."""

    def __init__(self, path: _StringOrPath, logger: LoggerProtocol):
        self.logger = logger
        self.path = Path(path)

    def _get_content(self, path: _StringOrPath, status: bool = False) -> Any:
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
            return [x for x in Path(path).iterdir()]
        except FileNotFoundError as e:
            self.logger.debug(f"{e} - {path}")
            return None
        except Exception as e:
            self.logger.error(f"{e} - {path}")
            return None
        return r

    def get(self, path: _StringOrPath) -> Any:
        p = Path.joinpath(self.path, path)
        r = self._get_content(p, status=False)
        return cvt(r)

    def get_text(self, path: _StringOrPath, default: str = "") -> str:
        t = self.get(path)
        return t.strip() if t else default

    def get_int(self, path: _StringOrPath, default: int = 0) -> int:
        t = self.get(path)
        return int(t) if t else default

    def check(self) -> bool:
        return self._get_content(self.path, status=True)

    def check_file(self, path: _StringOrPath) -> bool:
        p = Path.joinpath(self.path, path)
        return self._get_content(p, status=True)

    def get_bytes(self, path: _StringOrPath) -> bytes:
        p = Path.joinpath(self.path, path)
        r = self._get_content(p, status=False)
        return r

    def get_file_mtime(self, path: _StringOrPath) -> Union[None, datetime.datetime]:
        p = Path.joinpath(self.path, path)
        try:
            mtime = p.stat().st_mtime
        except FileNotFoundError:
            return None
        return cvt_ts_to_datetime(mtime, use_local_tz=False)

    def get_file_size(self, path: _StringOrPath) -> int:
        p = Path.joinpath(self.path, path)
        try:
            file_size = p.stat().st_size
        except FileNotFoundError:
            return 0
        return file_size

    def get_header(self, path: _StringOrPath) -> dict:
        return PackageHandler.get_header(str(Path.joinpath(self.path, path)))

    def get_file_path(self, path: _StringOrPath) -> Path:
        return Path.joinpath(self.path, path)

    def file_exists_and_not_empty(self, path: _StringOrPath) -> bool:
        p = Path.joinpath(self.path, path)
        if p.is_file() and p.stat().st_size > 0:
            return True
        else:
            return False

    def get_symlink_target(
        self, path: _StringOrPath, name_only: bool = False
    ) -> Union[None, str]:
        symlink = Path.joinpath(self.path, path)
        if symlink.is_symlink():
            if name_only:
                return str(symlink.resolve().name)
            else:
                return str(symlink.resolve())
        else:
            return None


class TaskFilesParser:
    def __init__(self, logger: LoggerProtocol):
        self.logger = logger

    def parse_approval_file(
        self, path: _StringOrPath
    ) -> Union[None, tuple[str, datetime.datetime, str]]:
        try:
            content = Path(path).read_text()
        except (FileNotFoundError, IsADirectoryError):
            return None
        n = d = m = None
        if content:
            try:
                d, *m = [x for x in content.split("\n") if len(x) > 0]
                d, n = [x.strip() for x in d.split("::") if len(x) > 0]
                n = n.split(" ")[-1]
                d = datetime.datetime.strptime(d, "%Y-%b-%d %H:%M:%S")
                d = set_datetime_timezone_to_utc(d)
                m = "\n".join((x for x in m))
                return (n, d, m)
            except Exception as e:
                self.logger.error(
                    f"File parsing failed with error {e} for '{path}' contains '{content}'"
                )
        return None

    @staticmethod
    def parse_pkglist_diff(
        diff_file: _StringOrPath, is_src_list: bool
    ) -> tuple[list[TaskPlanDiffPkgInfo], list[TaskPlanDiffPkgInfo]]:
        """Parse package list diff file. Returns tuple of added and deleted packages lists."""

        diff_pattern = re.compile("^[+-]+[a-zA-Z0-9]+\S+")  # type: ignore
        p_added: list[TaskPlanDiffPkgInfo] = []
        p_deleted: list[TaskPlanDiffPkgInfo] = []
        try:
            contents = Path(diff_file).read_text()
            contents = (x for x in contents.split("\n") if len(x) > 0)
        except FileNotFoundError:
            return [], []
        for line in contents:
            p = diff_pattern.findall(line)
            if p:
                sign = p[0][0]
                if is_src_list:
                    pkg_name = p[0][1:].strip()
                    pkg_evr, pkg_file = [
                        x.strip()
                        for x in diff_pattern.split(line)[-1].split("\t")
                        if len(x) > 0
                    ]
                    pkg_src = pkg_file
                    pkg_arch = "src"
                else:
                    pkg_name = p[0][1:].strip()
                    pkg_evr, pkg_arch, pkg_file, pkg_src = [
                        x.strip()
                        for x in diff_pattern.split(line)[-1].split("\t")
                        if len(x) > 0
                    ]
                if sign == "+":
                    p_added.append(
                        TaskPlanDiffPkgInfo(
                            pkg_name, pkg_evr, pkg_file, pkg_src, pkg_arch
                        )
                    )
                else:
                    p_deleted.append(
                        TaskPlanDiffPkgInfo(
                            pkg_name, pkg_evr, pkg_file, pkg_src, pkg_arch
                        )
                    )
        return p_added, p_deleted

    @staticmethod
    def parse_add_rm_plan(
        fname: _StringOrPath, is_add: bool, is_src: bool
    ) -> list[TaskPlanAddRmPkgInfo]:
        """Parse task plan package add/delete files. Return list of packages."""

        res: list[TaskPlanAddRmPkgInfo] = []
        try:
            contents = Path(fname).read_text()
            contents = (x for x in contents.split("\n") if len(x) > 0)
        except FileNotFoundError:
            return res
        for line in contents:
            s = line.split("\t")
            if is_add:
                # parse 'add-src' or 'add-bin' file
                if is_src:  # parse 'add-src' file
                    res.append(
                        TaskPlanAddRmPkgInfo(*s[0:2], "src", *s[2:4], int(s[4]), "")  # type: ignore
                    )
                else:  # parse 'add-bin' file
                    if len(s) >= 7:
                        res.append(TaskPlanAddRmPkgInfo(*s[0:5], int(s[5]), s[6]))  # type: ignore
                    else:
                        res.append(TaskPlanAddRmPkgInfo(*s[0:5], int(s[5]), ""))  # type: ignore
            else:
                # parse 'rm-src' or 'rm-bin' file
                if is_src:  # parse 'rm-src' file
                    res.append(
                        TaskPlanAddRmPkgInfo(*s[0:2], "src", s[2], "", 0, "")  # type: ignore
                    )
                else:  # parse 'rm-bin' file
                    if len(s) >= 5:
                        res.append(TaskPlanAddRmPkgInfo(*s[0:4], "", 0, s[4]))  # type: ignore
                    else:
                        res.append(TaskPlanAddRmPkgInfo(*s, "", 0, ""))  # type: ignore
        return res

    @staticmethod
    def parse_hash_diff(hash_file: _StringOrPath) -> tuple[dict, dict]:
        """Parse hash diff file. Returns added and deleted hashes as dictionaries."""

        hash_pattern = re.compile("^[+-]+[0-9a-f]{64}\s+")  # type: ignore
        h_added: dict[str, bytes] = {}
        h_deleted: dict[str, bytes] = {}
        try:
            contents = Path(hash_file).read_text()
            contents = (x for x in contents.split("\n") if len(x) > 0)
        except FileNotFoundError:
            return {}, {}
        for line in contents:
            h = hash_pattern.findall(line)
            if h:
                sign = h[0][0]
                sha256 = h[0][1:].strip()
                pkg_name = hash_pattern.split(line)[-1].strip()
                if sign == "+":
                    h_added[pkg_name] = bytes.fromhex(sha256)
                else:
                    h_deleted[pkg_name] = bytes.fromhex(sha256)
        return h_added, h_deleted

    def log_parser(
        self,
        log_file: _StringOrPath,
        log_type: str,
        log_start_time: datetime.datetime,
    ) -> Generator:
        """Task logs parser generator

        Args:
            log_file (str): log file name
            log_type (str): log type ('events'|'build'|'srpm')
            log_start_time (datetime): log start time for logs with
            partial or none timestamps included

        Returns:
            generator(tuple(int, datetime, str)): return parsed log as
            generator of tuples of line number, timestamp and message
        """
        # matches with '2020-May-15 10:30:00 '
        events_pattern = re.compile("^\d{4}-[A-Z][a-z]{2}-\d{2}\s\d{2}:\d{2}:\d{2}")  # type: ignore
        # matches with '<13>Sep 13 17:53:14 '
        srpm_pattern = re.compile("^<\d+>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}")  # type: ignore
        # matches with '[00:03:15] '
        build_pattern = re.compile("^\[\d{2}:\d{2}:\d{2}\]")  # type: ignore

        LogLine = namedtuple("LogLine", ["line", "ts", "message"])

        if not Path(log_file).is_file():
            self.logger.error(f"File '{log_file}' not found")
            return tuple()

        if log_type == "srpm" and not isinstance(log_start_time, datetime.datetime):
            self.logger.error(
                f"Valid 'log_start_time' value is required to parse 'srpm.log'"
                f" type file {log_file}. Log file parsing aborted."
            )
            return tuple()

        first_line = True
        line_cnt = 0

        # srpm build log parser
        def srpm_log(line: str) -> tuple:
            nonlocal line_cnt
            nonlocal first_line

            line_cnt += 1
            dt = srpm_pattern.findall(line)
            msg = srpm_pattern.split(line)[-1].strip()

            if dt:
                dt = dt[0]
                srpm_log.last_dt = dt
                first_line = False
                # XXX: workaround for 'Feb 29' (https://bugs.python.org/issue26460)
                ts_str = f"{str(log_start_time.year)} " + " ".join(
                    [x for x in dt[4:].split(" ") if len(x) > 0]
                )
                ts = datetime.datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
            else:
                if first_line:
                    self.logger.debug(
                        f"File '{log_file}' first line doesn't contain valid datetime."
                        f" Using 'log_start_time' as timestamp."
                    )
                    ts = log_start_time
                else:
                    ts_str = f"{str(log_start_time.year)} " + " ".join(
                        [x for x in srpm_log.last_dt[4:].split(" ") if len(x) > 0]  # type: ignore
                    )
                    ts = datetime.datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")

            return LogLine(line_cnt, ts, msg)

        # static-like function variable
        srpm_log.last_dt = None

        # build log parser
        def build_log(line: str) -> tuple:
            nonlocal line_cnt
            nonlocal first_line

            line_cnt += 1
            ts = build_pattern.findall(line)
            msg = build_pattern.split(line)[-1].strip()
            if ts:
                ts = ts[0][1:-1].split(":")
                ts = log_start_time + datetime.timedelta(
                    hours=int(ts[0]), minutes=int(ts[1]), seconds=int(ts[2])
                )
            else:
                ts = log_start_time

            return LogLine(line=line_cnt, ts=ts, message=msg)

        # events log parser
        def events_log(line: str) -> tuple:
            nonlocal line_cnt
            nonlocal first_line

            line_cnt += 1
            dt = events_pattern.findall(line)
            msg = events_pattern.split(line)[-1].split(" :: ")[-1].strip()

            if first_line:
                if not dt:
                    self.logger.error(
                        f"File '{log_file}' first line doesn't contain"
                        f" valid datetime. Log file parsing aborted."
                    )
                    return tuple()
                dt = dt[0]
                events_log.last_dt = dt
                first_line = False
                ts = datetime.datetime.strptime(dt, "%Y-%b-%d %H:%M:%S")
            else:
                if dt:
                    dt = dt[0]
                    events_log.last_dt = dt
                    ts = datetime.datetime.strptime(dt, "%Y-%b-%d %H:%M:%S")
                else:
                    ts = datetime.datetime.strptime(
                        events_log.last_dt, "%Y-%b-%d %H:%M:%S"
                    )

            return LogLine(line=line_cnt, ts=ts, message=msg)

        # static-like function variable
        events_log.last_dt = None

        type_to_parser = {"srpm": srpm_log, "build": build_log, "events": events_log}

        parser = type_to_parser.get(log_type, None)
        if parser is None:
            self.logger.error(
                f"Unknown log format specifier '{log_type}'."
                " Log file parsing aborted."
            )
            return tuple()

        with Path(log_file).open("r", encoding="utf-8", errors="backslashreplace") as f:
            for line in f:
                if len(line) > 0:  # skip an empty lines
                    p = parser(line)
                    if not p:
                        return p
                    else:
                        yield p


class LogLoaderWorker(RaisingTread):
    def __init__(
        self,
        conn: DatabaseClient,
        taskfs: TaskFromFileSystem,
        taskfp: TaskFilesParser,
        logger: LoggerProtocol,
        logs: Iterator[TaskLog],
        count_list: list,
        *args,
        **kwargs,
    ) -> None:
        self.conn = conn
        self.taskfs = taskfs
        self.taskfp = taskfp
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
                log_start_time = self.taskfs.get_file_mtime(log.path)
                log_file_size = self.taskfs.get_file_size(log.path)
                log_file = self.taskfs.get_file_path(log.path)
                log_parsed = GeneratorWrapper(
                    self.taskfp.log_parser(log_file, log.type, log_start_time)  # type: ignore
                )
                if log_parsed:
                    count += 1
                    self.conn.execute(
                        "INSERT INTO TaskLogs_buffer (*) VALUES",
                        (
                            dict(
                                tlog_hash=log.hash,
                                tlog_line=l,
                                tlog_ts=t,
                                tlog_message=m,
                            )
                            for l, t, m in log_parsed
                        ),
                    )
                    self.logger.debug(
                        f"Logfile loaded in {(time.time() - st):.3f} seconds "
                        f": {log.path} : {log_file_size} bytes"
                    )
                else:
                    self.logger.debug(f"Logfile parsing failed for {log.path}")
            except Exception as error:
                self.logger.error(str(error), exc_info=True)
                self.exc = error
                self.exc_message = f"Exception in thread {self.name} for log {log.path}"  # type: ignore
                self.exc_traceback = traceback.format_exc()
                break
        self.logger.debug(f"thread {self.ident} stop")
        self.count_list.append(count)


def log_load_worker_pool(
    conf: TaskProcessorConfig,
    taskfs: TaskFromFileSystem,
    logger: LoggerProtocol,
    logs_list: list[TaskLog],
    num_of_workers=0,
):
    # TODO: add progress bar
    st = time.time()
    taskfp = TaskFilesParser(logger)
    workers: list[RaisingTread] = []
    connections: list[DatabaseClient] = []
    logs: Iterator[TaskLog] = LockedIterator((log for log in logs_list))  # type: ignore
    logs_count: list[int] = []
    if not num_of_workers:
        num_of_workers = conf.workers

    for i in range(num_of_workers):
        conn = DatabaseClient(conf.dbconfig, logger)
        connections.append(conn)
        worker = LogLoaderWorker(
            conn=conn,
            logger=logger,
            taskfs=taskfs,
            taskfp=taskfp,
            logs=logs,
            count_list=logs_count,
        )
        worker.start()
        workers.append(worker)

    try:
        for w in workers:
            w.join()
    except RaisingThreadError as e:
        logger.error(e.message)
        raise e
    finally:
        for c in connections:
            if c is not None:
                c.disconnect()

    logger.info(
        f"{sum(logs_count)} log files loaded in {(time.time() - st):.3f} seconds"
    )


class TaskIterationLoaderWorker(RaisingTread):
    def __init__(
        self,
        conn: DatabaseClient,
        taskfs: TaskFromFileSystem,
        logger: LoggerProtocol,
        pkg_hashes_cache: set[int],
        task_pkg_hashes: dict[str, PkgHash],
        task_logs: list[TaskLog],
        task_iterations: Iterator[TaskIteration],
        count_list: list[int],
        lock: threading.Lock,
        *args,
        **kwargs,
    ) -> None:
        self.conn = conn
        self.taskfs = taskfs
        self.logger = logger
        self.cache = pkg_hashes_cache
        self.pkg_hashes = task_pkg_hashes
        self.task_logs = task_logs
        self.titers = task_iterations
        self.count_list = count_list
        self.count = 0
        self.lock = lock
        self.ph = PackageHandler(conn=conn, logger=logger)
        super().__init__(*args, **kwargs)

    def _calculate_hash_from_array_by_CH(self, hashes: list) -> int:
        sql = "SELECT murmurHash3_64(%(hashes)s)"
        r = self.conn.execute(sql, {"hashes": hashes})
        return int(r[0][0])

    def _insert_package(self, pkg: str, srpm_hash: int, is_srpm: bool) -> int:
        st = time.time()
        kw = {}
        hdr = self.taskfs.get_header(pkg)
        sha1 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_SHA1HEADER]))
        hashes = {"sha1": sha1, "mmh": snowflake_id_pkg(hdr)}
        pkg_name = Path(pkg).name

        kw["pkg_hash"] = hashes["mmh"]
        kw["pkg_filename"] = pkg_name
        kw["pkg_filesize"] = self.taskfs.get_file_size(pkg)
        if is_srpm:
            kw["pkg_sourcerpm"] = pkg_name
            kw["pkg_srcrpm_hash"] = hashes["mmh"]
        else:
            kw["pkg_srcrpm_hash"] = srpm_hash

        if not check_package_in_cache(self.cache, hashes["mmh"]):
            if self.pkg_hashes[pkg_name].md5:
                hashes["md5"] = self.pkg_hashes[pkg_name].md5
            else:
                self.logger.debug(f"calculate MD5 for {pkg_name} file")
                hashes["md5"] = md5_from_file(
                    self.taskfs.get_file_path(pkg), as_bytes=True
                )

            if self.pkg_hashes[pkg_name].sha256:
                hashes["sha256"] = self.pkg_hashes[pkg_name].sha256
            else:
                self.logger.debug(f"calculate SHA256 for {pkg_name} file")
                hashes["sha256"] = sha256_from_file(
                    self.taskfs.get_file_path(pkg), as_bytes=True
                )

            if self.pkg_hashes[pkg_name].blake2b not in (b"", None):
                hashes["blake2b"] = self.pkg_hashes[pkg_name].blake2b
            else:
                self.logger.debug(f"calculate BLAKE2b for {pkg_name} file")
                hashes["blake2b"] = blake2b_from_file(
                    self.taskfs.get_file_path(pkg), as_bytes=True
                )

            self.ph.insert_package(hdr, self.taskfs.get_file_path(pkg), **kw)
            self.ph.insert_pkg_hash_single(hashes)
            self.cache.add(hashes["mmh"])
            self.count += 1
            self.logger.debug(
                f"package loaded in {(time.time() - st):.3f} seconds :"
                f" {hashes['sha1'].hex()} : {kw['pkg_filename']}"
            )
        else:
            self.logger.debug(
                f"package already loaded : {hashes['sha1'].hex()} :"
                f" {kw['pkg_filename']}"
            )

        return hashes["mmh"]

    def run(self) -> None:
        self.logger.debug(f"thread {self.ident} start")
        count = 0
        for ti in self.titers:
            titer = {
                "task_id": ti.task_id,
                "subtask_id": ti.subtask_id,
                "task_changed": ti.task_changed,
                "subtask_arch": ti.subtask_arch,
                "titer_ts": ti.titer_ts,
                "task_try": ti.task_try,
                "task_iter": ti.task_iter,
                "titer_status": ti.titer_status,
                "titer_chroot_br": ti.titer_chroot_br,
                "titer_chroot_base": ti.titer_chroot_base,
            }
            try:
                # 1 - load packages
                titer["titer_srcrpm_hash"] = 0
                titer["titer_pkgs_hash"] = []
                subtask = str(titer["subtask_id"])
                arch = titer["subtask_arch"]
                # 1.1 - load srpm package
                with self.lock:
                    if ti.titer_srpm:
                        titer["titer_srcrpm_hash"] = self._insert_package(
                            ti.titer_srpm, 0, is_srpm=True
                        )
                    else:
                        titer["titer_srcrpm_hash"] = 0
                # 1.2 - load binary packages
                for pkg in ti.titer_rpms:
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
                for log in [x for x in self.task_logs if x.type in ("srpm", "build")]:
                    log_subtask, log_arch = log.path.split("/")[1:3]
                    if log_subtask == subtask and log_arch == arch:
                        if log.type == "srpm":
                            titer["titer_srpmlog_hash"] = log.hash
                        elif log.type == "build":
                            titer["titer_buildlog_hash"] = log.hash
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
                self.logger.error(str(error), exc_info=True)
                self.exc = error
                self.exc_message = (
                    f"Exception in thread {self.name} for task iteration "
                    f"{titer['task_id']} {titer['subtask_id']}"
                )
                self.exc_traceback = traceback.format_exc()
                break
            self.logger.info(
                f"{self.count} packages loaded from /build/{subtask}/{arch}"
            )
            if self.count:
                self.count = 0
        self.logger.debug(f"thread {self.ident} stop")
        self.count_list.append(count)


def titer_load_worker_pool(
    conf: TaskProcessorConfig,
    conn: DatabaseClient,
    taskfs: TaskFromFileSystem,
    logger: LoggerProtocol,
    task: Task,
    num_of_workers=0,
):
    # TODO: add progress bar
    st = time.time()
    workers: list[RaisingTread] = []
    connections: list[DatabaseClient] = []
    titer_count: list[int] = []
    titers: Iterator[TaskIteration] = LockedIterator((t for t in task.iterations))  # type: ignore
    src_load_lock = threading.Lock()

    if not num_of_workers:
        num_of_workers = conf.workers

    packages_ = []
    for titer in task.iterations:
        if titer.titer_srpm:
            packages_.append(titer.titer_srpm)
        for pkg in titer.titer_rpms:
            packages_.append(pkg)

    if not conf.force:
        pkg_hashes_cache = init_cache(conn, packages_, logger)
    else:
        pkg_hashes_cache = set()

    for i in range(num_of_workers):
        conn = DatabaseClient(conf.dbconfig, logger)
        connections.append(conn)
        worker = TaskIterationLoaderWorker(
            conn,
            taskfs,
            logger,
            pkg_hashes_cache,
            task.pkg_hashes,
            task.logs,
            titers,
            titer_count,
            src_load_lock,
        )
        worker.start()
        workers.append(worker)

    try:
        for w in workers:
            w.join()
    except RaisingThreadError as e:
        logger.error(e.message)
        raise e
    finally:
        for c in connections:
            if c is not None:
                c.disconnect()

    logger.info(
        f"{sum(titer_count)} TaskIteration loaded in {(time.time() - st):.3f} seconds"
    )


class PackageLoaderWorker(RaisingTread):
    def __init__(
        self,
        conn: DatabaseClient,
        taskfs: TaskFromFileSystem,
        logger: LoggerProtocol,
        pkg_hashes_cache: set[int],
        task_pkg_hashes: dict[str, PkgHash],
        packages: Iterator[str],
        count_list: list[int],
        *args,
        **kwargs,
    ) -> None:
        self.conn = conn
        self.taskfs = taskfs
        self.logger = logger
        self.cache = pkg_hashes_cache
        self.pkg_hashes = task_pkg_hashes
        self.packages = packages
        self.count_list = count_list
        self.count = 0
        self.ph = PackageHandler(conn=conn, logger=logger)
        super().__init__(*args, **kwargs)

    def _insert_package(self, pkg, srpm_hash, is_srpm):
        st = time.time()
        kw = {}
        hdr = self.taskfs.get_header(pkg)
        sha1 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_SHA1HEADER]))
        hashes = {"sha1": sha1, "mmh": snowflake_id_pkg(hdr)}
        pkg_name = Path(pkg).name

        if self.pkg_hashes[pkg_name].md5:
            hashes["md5"] = self.pkg_hashes[pkg_name].md5
        else:
            self.logger.debug(f"calculate MD5 for {pkg_name} file")
            hashes["md5"] = md5_from_file(self.taskfs.get_file_path(pkg), as_bytes=True)

        if self.pkg_hashes[pkg_name].sha256:
            hashes["sha256"] = self.pkg_hashes[pkg_name].sha256
        else:
            self.logger.debug(f"calculate SHA256 for {pkg_name} file")
            hashes["sha256"] = sha256_from_file(
                self.taskfs.get_file_path(pkg), as_bytes=True
            )

        if self.pkg_hashes[pkg_name].blake2b not in (b"", None):
            hashes["blake2b"] = self.pkg_hashes[pkg_name].blake2b
        else:
            self.logger.debug(f"calculate BLAKE2b for {pkg_name} file")
            hashes["blake2b"] = blake2b_from_file(
                self.taskfs.get_file_path(pkg), as_bytes=True
            )

        kw["pkg_hash"] = hashes["mmh"]
        kw["pkg_filename"] = pkg_name
        kw["pkg_filesize"] = self.taskfs.get_file_size(pkg)
        if is_srpm:
            kw["pkg_sourcerpm"] = pkg_name
            kw["pkg_srcrpm_hash"] = hashes["mmh"]
        else:
            kw["pkg_srcrpm_hash"] = srpm_hash

        if not check_package_in_cache(self.cache, hashes["mmh"]):
            self.ph.insert_package(hdr, self.taskfs.get_file_path(pkg), **kw)
            self.ph.insert_pkg_hash_single(hashes)
            self.cache.add(hashes["mmh"])
            self.count += 1
            self.logger.debug(
                f"package loaded in {(time.time() - st):.3f} seconds :"
                f" {hashes['sha1'].hex()} : {kw['pkg_filename']}"
            )
        else:
            self.logger.debug(
                f"package already loaded : {hashes['sha1'].hex()} : "
                f"{kw['pkg_filename']}"
            )

        return hashes["mmh"]

    def run(self):
        self.logger.debug(f"thread {self.ident} start")
        for pkg in self.packages:
            try:
                self._insert_package(pkg, 0, is_srpm=False)
            except Exception as error:
                self.logger.error(str(error), exc_info=True)
                self.exc = error
                self.exc_message = f"Exception in thread {self.name} for package {pkg}"
                self.exc_traceback = traceback.format_exc()
                break
        self.logger.debug(f"thread {self.ident} stop")
        self.count_list.append(self.count)


def package_load_worker_pool(
    conf: TaskProcessorConfig,
    conn: DatabaseClient,
    taskfs: TaskFromFileSystem,
    logger: LoggerProtocol,
    task: Task,
    num_of_workers: int = 0,
    loaded_from="",
):
    # TODO: add progress bar
    st = time.time()
    workers: list[RaisingTread] = []
    pkg_count: list[int] = []
    connections: list[DatabaseClient] = []
    packages: Iterator[str] = LockedIterator((pkg for pkg in task.arepo))  # type: ignore

    if not conf.force:
        pkg_hashes_cache = init_cache(conn, task.arepo, logger)
    else:
        pkg_hashes_cache = set()

    if not num_of_workers:
        num_of_workers = conf.workers

    for i in range(num_of_workers):
        conn = DatabaseClient(conf.dbconfig, logger)
        connections.append(conn)
        worker = PackageLoaderWorker(
            conn,
            taskfs,
            logger,
            pkg_hashes_cache,
            task.pkg_hashes,
            packages,
            pkg_count,
        )
        worker.start()
        workers.append(worker)

    try:
        for w in workers:
            w.join()
    except RaisingThreadError as e:
        logger.error(e.message)
        raise e
    finally:
        for c in connections:
            if c is not None:
                c.disconnect()

    if sum(pkg_count):
        logger.info(
            f"{sum(pkg_count)} packages loaded in {(time.time() - st):.3f}"
            f" seconds from {loaded_from}"
        )


class TaskLoadHandler:
    """Handles task structure loading to DB."""

    def __init__(
        self,
        conn: DatabaseClient,
        taskfs: TaskFromFileSystem,
        logger: LoggerProtocol,
        task: Task,
        conf: TaskProcessorConfig,
    ):
        self.tf = taskfs
        self.conf = conf
        self.task = task
        self.conn = conn
        self.logger = logger
        self.approvals = []

    def _save_task(self):
        # 1 - proceed with TaskStates
        # 1.1 - save event logs hashes
        eventlog_hash = [x.hash for x in self.task.logs if x.type == "events"]
        # 1.2 - save current task state
        state = {
            "task_changed": self.task.state.changed,
            "task_id": self.task.state.task_id,
            "task_state": self.task.state.state,
            "task_runby": self.task.state.runby,
            "task_depends": self.task.state.depends,
            "task_try": self.task.state.task_try,
            "task_testonly": self.task.state.testonly,
            "task_failearly": self.task.state.failearly,
            "task_shared": self.task.state.shared,
            "task_message": self.task.state.message,
            "task_version": self.task.state.version,
            "task_prev": self.task.state.prev,
            "task_eventlog_hash": eventlog_hash,
        }
        self.conn.execute("INSERT INTO TaskStates_buffer (*) VALUES", [state])
        # 2 - proceed with TaskApprovals
        # 2.1 - collect task approvals from DB
        Approval = namedtuple(
            "Approval",
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
            {"task_id": self.task.state.task_id},
        )
        tapps_from_db = [Approval(*x[0])._asdict() for x in res]
        for tapp in tapps_from_db:
            tapp["tapp_date"] = cvt_datetime_local_to_utc(tapp["tapp_date"])

        tapps_from_fs = [
            {
                "task_id": x.task_id,
                "subtask_id": x.subtask_id,
                "tapp_type": x.type,
                "tapp_revoked": x.revoked,
                "tapp_date": x.date,
                "tapp_name": x.name,
                "tapp_message": x.message,
            }
            for x in self.task.approvals
        ]

        # 2.2 - collect previous approvals from DB that are not rewoked
        tapps = []
        for tapp in deepcopy(tapps_from_db):
            if tapp["tapp_revoked"] == 0:
                tapp["tapp_revoked"] = None
                tapps.append(tapp)
        # 2.3 - find rewoked by compare DB and actual task approvals
        tapps_revoked = []
        for tapp in tapps:
            if tapp not in tapps_from_fs:
                tapp["tapp_revoked"] = 1
                tapp["tapp_date"] = cvt_datetime_local_to_utc(datetime.datetime.now())
                tapps_revoked.append(tapp)
        # 2.4 - set 'tapp_rewoked' flag for new and not revoked ones
        for tapp in tapps_from_fs:
            if tapp["tapp_revoked"] is None:
                tapp["tapp_revoked"] = 0
        tapps_from_fs += tapps_revoked
        # 2.5 - remove task approvals that already in database
        new_task_approvals = []
        for tapp in tapps_from_fs:
            if tapp not in tapps_from_db:
                new_task_approvals.append(tapp)
        # 2.6 - load new approvals state to DB
        if new_task_approvals:
            self.conn.execute(
                "INSERT INTO TaskApprovals (*) VALUES", new_task_approvals
            )
        # 3 - proceed with Tasks
        subtasks = []
        for sub in self.task.subtasks:
            subtasks.append(
                {
                    "task_id": sub.task_id,
                    "subtask_id": sub.subtask_id,
                    "task_repo": sub.task_repo,
                    "task_owner": sub.task_owner,
                    "task_changed": sub.task_changed,
                    "subtask_changed": sub.subtask_changed,
                    "subtask_deleted": sub.deleted,
                    "subtask_userid": sub.userid,
                    "subtask_dir": sub.dir,
                    "subtask_package": sub.package,
                    "subtask_type": sub.type,
                    "subtask_pkg_from": sub.pkg_from,
                    "subtask_sid": sub.sid,
                    "subtask_tag_author": sub.tag_author,
                    "subtask_tag_id": sub.tag_id,
                    "subtask_tag_name": sub.tag_name,
                    "subtask_srpm": sub.srpm,
                    "subtask_srpm_name": sub.srpm_name,
                    "subtask_srpm_evr": sub.srpm_evr,
                }
            )
        if subtasks:
            self.conn.execute("INSERT INTO Tasks_buffer (*) VALUES", subtasks)
        # 4 - load all logs
        if self.task.logs:
            log_load_worker_pool(
                self.conf,
                self.tf,
                self.logger,
                self.task.logs,
                num_of_workers=None,
            )
        # 5 - proceed with TaskIterations
        if self.task.iterations:
            titer_load_worker_pool(
                self.conf,
                self.conn,
                self.tf,
                self.logger,
                self.task,
                num_of_workers=None,
            )
        # 6 - load arepo packages
        if self.task.arepo:
            package_load_worker_pool(
                self.conf,
                self.conn,
                self.tf,
                self.logger,
                self.task,
                num_of_workers=0,
                loaded_from="'/arepo'",
            )
        # 7 - load plan
        # 7.1 - load plan package added and deleted
        payload = []
        for arch in self.task.plan.pkg_add.keys():
            for file, pkg in self.task.plan.pkg_add[arch].items():
                payload.append(
                    {
                        "tplan_hash": self.task.plan.hashes[arch],
                        "tplan_action": "add",
                        "tplan_pkg_name": pkg.name,
                        "tplan_pkg_evr": pkg.evr,
                        "tplan_bin_file": file,
                        "tplan_src_file": pkg.srpm,
                        "tplan_arch": pkg.arch,
                        "tplan_comp": pkg.comp,
                        "tplan_subtask": pkg.subtask_id,
                    }
                )
        for arch in self.task.plan.pkg_del.keys():
            for file, pkg in self.task.plan.pkg_del[arch].items():
                payload.append(
                    {
                        "tplan_hash": self.task.plan.hashes[arch],
                        "tplan_action": "delete",
                        "tplan_pkg_name": pkg.name,
                        "tplan_pkg_evr": pkg.evr,
                        "tplan_bin_file": file,
                        "tplan_src_file": pkg.srpm,
                        "tplan_arch": pkg.arch,
                        "tplan_comp": pkg.comp,
                        "tplan_subtask": pkg.subtask_id,
                    }
                )
        if payload:
            self.conn.execute("""INSERT INTO TaskPlanPackages (*) VALUES""", payload)
        # 7.2 - load plan package hashes add and delete
        payload = []
        for arch in self.task.plan.hash_add.keys():
            for hash in self.task.plan.hash_add[arch].values():
                payload.append(
                    {
                        "tplan_hash": self.task.plan.hashes[arch],
                        "tplan_action": "add",
                        "tplan_sha256": hash,
                    }
                )
        for arch in self.task.plan.hash_del.keys():
            for hash in self.task.plan.hash_del[arch].values():
                payload.append(
                    {
                        "tplan_hash": self.task.plan.hashes[arch],
                        "tplan_action": "delete",
                        "tplan_sha256": hash,
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

    def _flush_buffer_tables(self):
        """Force flush bufeer tables using OPTIMIZE TABLE SQL requests."""
        buffer_tables = (
            "Files_buffer",
            "Depends_buffer",
            "Changelog_buffer",
            "Packages_buffer",
            "PackageHash_buffer",
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


class TaskParser:
    def __init__(self, task_path: _StringOrPath, logger: LoggerProtocol) -> None:
        self.tf = TaskFromFileSystem(path=task_path, logger=logger)
        self.tfp = TaskFilesParser(logger=logger)
        self.logger = logger
        self.task = Task(
            id=0,
            logs=[],
            arepo=[],
            subtasks=[],
            approvals=[],
            iterations=[],
            pkg_hashes=defaultdict(PkgHash),
            state=TaskState(task_id=0, state="", task_try=0, task_iter=0),
            plan=TaskPlan(hashes={}, pkg_add={}, pkg_del={}, hash_add={}, hash_del={}),
        )

    def _parse_task_state(self) -> None:
        # parse '/task' and '/info.json' for 'TaskStates'
        # get task ID
        self.task.id = self.tf.get_int("task/id")
        if self.task.id == 0:
            raise TaskLoaderParserError(f"Failed to get task ID. Aborting")
        self.task.state.task_id = self.task.id
        # get task state
        if self.tf.check_file("task/state"):
            self.task.state.state = self.tf.get("task/state").strip()
            self.task.state.changed = self.tf.get_file_mtime("task/state")
            t = self.tf.get_file_mtime("info.json")
            if t and t > self.task.state.changed:  # type: ignore
                self.task.state.changed = t
        else:
            # skip tasks with uncertain state for God sake
            raise TaskLoaderParserError(
                f"Failed to get task state for {self.task.id}. Aborting"
            )

        self.task.state.runby = self.tf.get_text("task/run")
        self.task.state.task_try = self.tf.get_int("task/try")
        self.task.state.task_iter = self.tf.get_int("task/iter")
        self.task.state.message = self.tf.get_text("task/message")
        self.task.state.version = self.tf.get_text("task/version")

        t = self.tf.get("task/depends")
        self.task.state.depends = (
            [int(x) for x in t.split("\n") if len(x) > 0] if t else []
        )

        self.task.state.testonly = 1 if self.tf.check_file("task/test-only") else 0
        self.task.state.failearly = 1 if self.tf.check_file("task/fail-early") else 0

        self.task.state.shared = (
            1 if val_from_json_str(self.tf.get("info.json"), "shared") else 0
        )

        t = self.tf.get_symlink_target("build/repo/prev", name_only=True)
        self.task.state.prev = int(t) if t else 0

    def _parse_task_plan(self) -> None:
        # parse '/plan' and '/build/repo' for diff lists and hashes
        # XXX: check if task '/plan' is up to date. Workaround for bug #40728
        load_plan = False
        if self.task.state.task_try != 0 and self.task.state.task_iter != 0:
            task_tryiter_time = max(
                self.tf.get_file_mtime("task/try"),  # type: ignore
                self.tf.get_file_mtime("task/iter")  # type: ignore
            )
            task_plan_time = self.tf.get_file_mtime("plan")
            if task_plan_time > task_tryiter_time:  # type: ignore
                load_plan = True
        # always load plan if task in 'DONE' state
        if self.task.state.state == "DONE":
            load_plan = True
        if load_plan:
            # 1 - get binary packages add and delete from plan
            pkgadd: dict[str, TaskPlanAddRmPkgInfo] = {}
            if self.tf.check_file("plan/add-src"):
                pkg_add = self.tfp.parse_add_rm_plan(
                    self.tf.get_file_path("plan/add-src"), is_add=True, is_src=True
                )
                for pkg in pkg_add:
                    pkgadd[pkg.file] = pkg
            if self.tf.check_file("plan/add-bin"):
                pkg_add = self.tfp.parse_add_rm_plan(
                    self.tf.get_file_path("plan/add-bin"), is_add=True, is_src=False
                )
                for pkg in pkg_add:
                    pkgadd[pkg.file] = pkg

            pkgdel: dict[str, TaskPlanAddRmPkgInfo] = {}
            if self.tf.check_file("plan/rm-src"):
                pkg_add = self.tfp.parse_add_rm_plan(
                    self.tf.get_file_path("plan/rm-src"), is_add=False, is_src=True
                )
                for pkg in pkg_add:
                    pkgdel[pkg.file] = pkg
            if self.tf.check_file("plan/rm-bin"):
                pkg_add = self.tfp.parse_add_rm_plan(
                    self.tf.get_file_path("plan/rm-bin"), is_add=False, is_src=False
                )
                for pkg in pkg_add:
                    pkgdel[pkg.file] = pkg

            # 2 - get packages list diffs
            empty_pkg_ = TaskPlanAddRmPkgInfo("", "", "", "", "", 0, "")
            for pkgdiff in (
                x for x in self.tf.get_file_path("plan").glob("*.list.diff")
            ):
                if pkgdiff.name == "src.list.diff":
                    p_add, p_del = self.tfp.parse_pkglist_diff(
                        pkgdiff, is_src_list=True
                    )
                else:
                    p_add, p_del = self.tfp.parse_pkglist_diff(
                        pkgdiff, is_src_list=False
                    )

                for p in p_add:
                    pp = pkgadd.get(p.file, empty_pkg_)
                    p_info = {
                        p.file: PkgInfo(
                            file=p.file,
                            name=p.name,
                            evr=p.evr,
                            srpm=p.srpm,
                            arch=p.arch,
                            comp=pp.comp,
                            path=pp.path,
                            subtask_id=pp.subtask_id,
                        )
                    }
                    if p.arch not in self.task.plan.pkg_add:
                        self.task.plan.pkg_add[p.arch] = {}
                    self.task.plan.pkg_add[p.arch].update(p_info)

                for p in p_del:
                    pp = pkgdel.get(p.file, empty_pkg_)
                    p_info = {
                        p.file: PkgInfo(
                            file=p.file,
                            name=p.name,
                            evr=p.evr,
                            srpm=p.srpm,
                            arch=p.arch,
                            comp=pp.comp,
                            path=pp.path,
                            subtask_id=pp.subtask_id,
                        )
                    }
                    if p.arch not in self.task.plan.pkg_del:
                        self.task.plan.pkg_del[p.arch] = {}
                    self.task.plan.pkg_del[p.arch].update(p_info)

            # 3 - get SHA256 hashes from '/plan/*.hash.diff'
            for hashdiff in (
                x for x in self.tf.get_file_path("plan").glob("*.hash.diff")
            ):
                h_add, h_del = self.tfp.parse_hash_diff(hashdiff)
                h_arch = hashdiff.name.split(".")[0]
                self.task.plan.hash_add[h_arch] = h_add
                self.task.plan.hash_del[h_arch] = h_del
                for k, v in h_add.items():
                    self.task.pkg_hashes[k] = PkgHash(sha256=v)

        # 2 - get MD5 and blake2b hashes from '/build/repo/%arch%/base/pkglist.task.xz'
        for pkglist in (
            x
            for x in self.tf.get_file_path("build/repo").glob("*/base/pkglist.task.xz")
        ):
            hdrs = readHeaderListFromXZFile(pkglist)
            for hdr in hdrs:
                pkg_name = cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYFILENAME])
                pkg_md5 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYMD5]))
                pkg_blake2b = bytes.fromhex(cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYBLAKE2B]))
                if pkg_name not in self.task.pkg_hashes:
                    self.task.pkg_hashes[pkg_name] = PkgHash()
                self.task.pkg_hashes[pkg_name].blake2b = pkg_blake2b
                # XXX: workaround for duplicated noarch packages with wrong MD5 from pkglist.task.xz
                if self.task.pkg_hashes[pkg_name].md5:
                    if self.task.pkg_hashes[pkg_name].md5 != pkg_md5:
                        self.logger.debug(
                            f"Found mismatching MD5 from APT hash for {pkg_name}."
                            "Calculating MD5 from file"
                        )
                        t = [
                            x
                            for x in self.tf.get_file_path("build/repo").glob(
                                f"*/RPMS.task/{pkg_name}"
                            )
                        ]
                        if t:
                            self.task.pkg_hashes[pkg_name].md5 = md5_from_file(  # type: ignore
                                t[0], as_bytes=True
                            )
                        else:
                            self.logger.error(
                                f"Failed to calculate MD5 for {pkg_name} from file"
                            )
                    else:
                        continue
                else:
                    self.task.pkg_hashes[pkg_name].md5 = pkg_md5

        # 3 - set hashes for TaskPlan* tables
        p_arch = {x for x in self.task.plan.pkg_add.keys()}
        p_arch.update({x for x in self.task.plan.pkg_del.keys()})
        p_arch.update({x for x in self.task.plan.hash_add.keys()})
        p_arch.update({x for x in self.task.plan.hash_del.keys()})
        for arch in p_arch:
            plan_hash = (
                ""
                + str(self.task.state.task_id)
                + str(self.task.state.task_try)
                + str(self.task.state.task_iter)
                + arch
            )
            self.task.plan.hashes[arch] = mmhash(plan_hash)

    def _parse_task_approvals(self) -> None:
        # parse '/acl' for 'TaskApprovals'
        # 1 - iterate through 'acl/approved'
        for subtask in (
            x.name
            for x in self.tf.get_file_path("acl/disapproved").glob("[0-7]*")
            if x.is_dir()
        ):
            subtask_dir = "/".join(("acl/approved", subtask))
            for approver in (x.name for x in self.tf.get(subtask_dir) if x.is_file()):
                t = self.tfp.parse_approval_file(
                    self.tf.get_file_path("/".join((subtask_dir, approver)))
                )
                if t:
                    self.task.approvals.append(
                        TaskApproval(
                            task_id=self.task.state.task_id,
                            subtask_id=int(subtask),
                            type="approve",
                            name=t[0],
                            date=t[1],
                            message=t[2],
                            revoked=None,
                        )
                    )
        # 2 - iterate through 'acl/dsiapproved'
        for subtask in (
            x.name
            for x in self.tf.get_file_path("acl/disapproved").glob("[0-7]*")
            if x.is_dir()
        ):
            subtask_dir = "/".join(("acl/disapproved", subtask))
            for approver in (x.name for x in self.tf.get(subtask_dir) if x.is_file()):
                t = self.tfp.parse_approval_file(
                    self.tf.get_file_path("/".join((subtask_dir, approver)))
                )
                if t:
                    self.task.approvals.append(
                        TaskApproval(
                            task_id=self.task.state.task_id,
                            subtask_id=int(subtask),
                            type="disapprove",
                            name=t[0],
                            date=t[1],
                            message=t[2],
                            revoked=None,
                        )
                    )

    def _parse_subtasks(self) -> None:
        # parse '/gears' for 'Tasks'
        for subtask in (
            x.name for x in self.tf.get_file_path("gears").glob("[0-7]*") if x.is_dir()
        ):
            subtask_dir = "/".join(("gears", subtask))
            files = set((x.name for x in self.tf.get(subtask_dir)))
            sid = self.tf.get("/".join((subtask_dir, "sid")))

            sub = TaskSubtask(
                task_id=self.task.state.task_id,
                subtask_id=int(subtask),
                task_repo=self.tf.get_text("task/repo"),
                task_owner=self.tf.get_text("task/owner"),
                task_changed=self.task.state.changed,
                subtask_changed=None,
                userid=self.tf.get_text("/".join((subtask_dir, "userid"))),
                sid=sid.split(":")[1].strip() if sid else "",
                type=sid.split(":")[0] if sid else "",
            )

            if self.tf.check_file("/".join((subtask_dir, "userid"))):
                sub.subtask_changed = self.tf.get_file_mtime(
                    "/".join((subtask_dir, "userid"))
                )
            else:
                sub.subtask_changed = self.tf.get_file_mtime(subtask_dir)

            if "dir" not in files and "srpm" not in files and "package" not in files:
                # deleted subtask
                sub.deleted = 1
                sub.type = "unknown"
            else:
                sub.deleted = 0
                # logic from girar-task-run check_copy_del()
                if self.tf.file_exists_and_not_empty(
                    "/".join((subtask_dir, "package"))
                ) and not self.tf.file_exists_and_not_empty(
                    "/".join((subtask_dir, "dir"))
                ):
                    if self.tf.file_exists_and_not_empty(
                        "/".join((subtask_dir, "copy_repo"))
                    ):
                        sub.type = "copy"
                        sub.pkg_from = self.tf.get_text(
                            "/".join((subtask_dir, "copy_repo"))
                        )
                    else:
                        sub.type = "delete"

                if self.tf.check_file("/".join((subtask_dir, "rebuild"))):
                    sub.type = "rebuild"
                    sub.pkg_from = self.tf.get_text("/".join((subtask_dir, "rebuild")))
                # changed in girar @ e74d8067009d
                if self.tf.check_file("/".join((subtask_dir, "rebuild_from"))):
                    sub.type = "rebuild"
                    sub.pkg_from = self.tf.get_text(
                        "/".join((subtask_dir, "rebuild_from"))
                    )
                if sub.type == "":
                    sub.type = "unknown"

                sub.dir = self.tf.get_text("/".join((subtask_dir, "dir")))
                sub.package = self.tf.get_text("/".join((subtask_dir, "package")))

                sub.tag_id = self.tf.get_text("/".join((subtask_dir, "tag_id")))
                sub.tag_name = self.tf.get_text("/".join((subtask_dir, "tag_name")))
                sub.tag_author = self.tf.get_text("/".join((subtask_dir, "tag_author")))

                sub.srpm = self.tf.get_text("/".join((subtask_dir, "srpm")))
                t = self.tf.get("/".join((subtask_dir, "nevr")))
                if t:
                    sub.srpm_name = t.split("\t")[0].strip()
                    sub.srpm_evr = t.split("\t")[1].strip()

            self.task.subtasks.append(sub)

    def _parse_iterations(self) -> None:
        # parse '/build' for 'TaskIterations'
        src_pkgs: dict[int, str] = {}
        bin_pkgs: dict[int, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        # 0 - get src and binary packages from plan
        t = self.tf.get_text("plan/add-src")
        if t:
            for *_, pkg_path, n in [x.split("\t") for x in t.split("\n") if len(x) > 0]:
                src_pkgs[int(n)] = pkg_path
        t = self.tf.get_text("plan/add-bin")
        if t:
            for _, _, arch, _, pkg_path, n, *_ in [
                x.split("\t") for x in t.split("\n") if len(x) > 0
            ]:
                bin_pkgs[int(n)][arch].append(pkg_path)
        # 1 - get contents from /build/%subtask_id%/%arch%
        for subtask in (
            x.name for x in self.tf.get_file_path("build").glob("[0-7]*") if x.is_dir()
        ):
            subtask_id = int(subtask)
            subtask_dir = "/".join(("build", subtask))
            # follow order of architectures from ARCHS list to prefer
            # source package from 'x86_64' and 'i586' architectures if there is no plan
            archs_fs = set((x.name for x in self.tf.get(subtask_dir) if x.is_dir()))
            archs = [x for x in ("x86_64", "i586") if x in archs_fs]
            archs += [x for x in archs_fs if x not in archs]
            for arch in archs:
                arch_dir = "/".join((subtask_dir, arch))

                ti = TaskIteration(
                    task_id=self.task.state.task_id,
                    task_changed=self.task.state.changed,
                    subtask_id=int(subtask),
                    subtask_arch=arch,
                )

                if self.tf.check_file("/".join((arch_dir, "status"))):
                    ts_ = self.tf.get_file_mtime("/".join((arch_dir, "status")))
                    ti.titer_status = self.tf.get_text(
                        "/".join((arch_dir, "status")), "failed"
                    )
                else:
                    ts_ = self.tf.get_file_mtime(arch_dir)
                    ti.titer_status = "failed"
                ti.titer_ts = ts_
                ti.task_try = self.task.state.task_try
                ti.task_iter = self.task.state.task_iter
                # read chroots
                chb_ = self.tf.get("/".join((arch_dir, "chroot_base")))
                if chb_:
                    for pkg in (
                        x.split("\t")[-1].strip() for x in chb_.split("\n") if len(x) > 0
                    ):
                        # FIXME: useless data due to packages stored with snowflake hash now!
                        ti.titer_chroot_base.append(mmhash(bytes.fromhex(pkg)))
                chbr_ = self.tf.get("/".join((arch_dir, "chroot_BR")))
                if chbr_:
                    for pkg in (
                        x.split("\t")[-1].strip() for x in chbr_.split("\n") if len(x) > 0
                    ):
                        # FIXME: useless data due to packages stored with snowflake hash now!
                        ti.titer_chroot_br.append(mmhash(bytes.fromhex(pkg)))
                # get src and bin packages
                pkgs_ = self.tf.get("/".join((arch_dir, "srpm")))
                if pkgs_ and len(pkgs_) > 0:
                    ti.titer_status = "built"
                    # skip srpm if got it from 'plan/add-src'
                    # XXX: handle particular srpm package loading somehow if plan exists
                    if subtask_id not in src_pkgs:
                        src_pkgs[subtask_id] = "/".join((arch_dir, "srpm", pkgs_[0].name))
                # set source rpm path
                ti.titer_srpm = src_pkgs.get(subtask_id, "")

                pkgs_ = self.tf.get("/".join((arch_dir, "rpms")))
                if pkgs_ and len(pkgs_) > 0:
                    ti.titer_status = "built"
                    bin_pkgs[subtask_id][arch] = []
                    for brpm in pkgs_:
                        bin_pkgs[subtask_id][arch].append(
                            "/".join((arch_dir, "rpms", brpm.name))
                        )

                if subtask_id in bin_pkgs and arch in bin_pkgs[subtask_id]:
                    ti.titer_rpms = [x for x in bin_pkgs[subtask_id][arch]]
                self.task.iterations.append(ti)
                # save build logs
                for log_file in ("log", "srpm.log"):
                    if self.tf.file_exists_and_not_empty(
                        "/".join((arch_dir, log_file))
                    ):
                        log_hash = (
                            ""
                            + str(ti.task_id)
                            + str(ti.subtask_id)
                            + str(ti.task_try)
                            + str(ti.task_iter)
                            + ti.subtask_arch
                        )
                        if log_file == "log":
                            log_hash = "build" + log_hash
                            self.task.logs.append(
                                TaskLog(
                                    type="build",
                                    path="/".join((arch_dir, log_file)),
                                    hash=mmhash(log_hash),
                                    hash_string=log_hash,
                                )
                            )
                        else:
                            log_hash = "srpm" + log_hash
                            self.task.logs.append(
                                TaskLog(
                                    type="srpm",
                                    path="/".join((arch_dir, log_file)),
                                    hash=mmhash(log_hash),
                                    hash_string=log_hash,
                                )
                            )
        # 2 - generate task iterations for subtask with 'delete' action
        build_subtasks = {x.subtask_id for x in self.task.iterations}
        for sub in self.task.subtasks:
            if sub.deleted == 0 and sub.type == "delete":
                if sub.subtask_id not in build_subtasks:
                    # create stub task iteration
                    self.task.iterations.append(
                        TaskIteration(
                            task_id=self.task.state.task_id,
                            task_changed=self.task.state.changed,
                            task_try=self.task.state.task_try,
                            task_iter=self.task.state.task_iter,
                            subtask_id=sub.subtask_id,
                            subtask_arch="x86_64",
                            titer_status="deleted",
                            titer_ts=self.tf.get_file_mtime("build"),
                        )
                    )

    def _parse_arepo_packages(self) -> None:
        # parse '/arepo' for packages
        t = self.tf.get("arepo/x86_64-i586/rpms")
        for pkg in (x.name for x in t if t and x.suffix == ".rpm"):
            self.task.arepo.append(f"arepo/x86_64-i586/rpms/{pkg}")

    def _parse_event_logs(self) -> None:
        # parse '/logs' for event logs
        for log_file in (
            x.name for x in self.tf.get_file_path("logs").glob("events.*.log")
        ):
            log_hash = (
                "events"
                + str(self.task.state.task_id)
                + log_file.split(".")[1]
                + log_file.split(".")[2]
            )
            self.task.logs.append(
                TaskLog(
                    type="events",
                    path="/".join(("logs", log_file)),
                    hash=mmhash(log_hash),
                    hash_string=log_hash,
                )
            )

    def read_task_structure(self) -> Task:
        self._parse_task_state()
        self._parse_task_plan()
        self._parse_task_approvals()
        self._parse_subtasks()
        self._parse_iterations()
        self._parse_event_logs()
        self._parse_arepo_packages()
        return self.task


class TaskProcessor:
    """Process and load Task to DB."""

    def __init__(self, config: TaskProcessorConfig) -> None:
        self.conn: DatabaseClient
        self.task: Task
        self.config = config

        if self.config.logger is not None:
            self.logger = self.config.logger
        else:
            self.logger = DEFAULT_LOGGER(name="task")

        if self.config.debug:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        self.task_parser = TaskParser(self.config.path, self.logger)
        self._check_config()

    def _check_config(self) -> None:
        # check if config is correct here
        if not self.task_parser.tf.check():
            self.logger.error(f"Invlaid task path {self.config.path}")
            raise TaskLoaderInvalidPathError(str(self.config.path))
        # create DB client and check connection
        self.conn = DatabaseClient(config=self.config.dbconfig, logger=self.logger)

    def run(self) -> None:
        ts = time.time()
        self.logger.info(f"reading task structure for {self.config.path}")
        self.task = self.task_parser.read_task_structure()
        self.logger.info(f"task structure loaded in {(time.time() - ts):.3f} seconds")
        if self.config.dumpjson:
            p = Path.joinpath(Path.cwd(), "JSON")
            p.mkdir(exist_ok=True)
            dump_to_json(
                # FIXME: Task object dictionary contains a long integers that out of JSON standard numbers range
                task_as_dict(self.task),
                Path.joinpath(
                    p,
                    (
                        f"dump-{str(self.task.state.task_id)}-"
                        f"{datetime.date.today().strftime('%Y-%m-%d')}.json"
                    ),
                ),
            )
        task_loader = TaskLoadHandler(
            self.conn, self.task_parser.tf, self.logger, self.task, self.config
        )
        self.logger.info(
            f"loading task {self.config.id} to database {self.config.dbconfig.name}"
        )
        try:
            task_loader.save()
            if self.config.flush:
                self.logger.info("Flushing buffer tables")
                task_loader.flush()
            # update Depends table
            task_loader.update_depends()
        except RaisingThreadError as exc:
            self.logger.error(
                f"An error ocured while loading task {self.config.id} to DB"
            )
            raise TaskLoaderProcessingError(self.config.id, exc) from exc
        except Exception as exc:
            self.logger.error(
                f"An error ocured while loading task {self.config.id} to DB",
                exc_info=True,
            )
            raise exc
        else:
            ts = time.time() - ts
            self.logger.info(f"task {self.config.id} loaded in {ts:.3f} seconds")
