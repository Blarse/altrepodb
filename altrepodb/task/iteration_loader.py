# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021-2022 BaseALT Ltd
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

import time
import logging
import threading
import traceback
from pathlib import Path
from typing import Iterator

from altrepodb.altrpm import rpm as rpmt
from altrepodb.base import LockedIterator, RaisingTread, PkgHash
from altrepodb.exceptions import RaisingThreadError
from altrepodb.utils import (
    hashes_from_file,
    md5_from_file,
    sha256_from_file,
    blake2b_from_file,
    check_package_in_cache,
)
from altrepodb.database import DatabaseClient
from altrepodb.repo.utils import convert
from altrepodb.repo.mapper import snowflake_id_pkg
from altrepodb.repo.package import PackageHandler

from .base import Task, TaskLog, TaskIteration, TaskProcessorConfig
from .reader import TaskFromFileSystem
from .utils import init_cache


class TaskIterationLoaderWorker(RaisingTread):
    def __init__(
        self,
        conn: DatabaseClient,
        taskfs: TaskFromFileSystem,
        logger: logging.Logger,
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
        self.ph = PackageHandler(conn=conn)
        super().__init__(*args, **kwargs)

    def _calculate_hash_from_array_by_CH(self, hashes: list[int]) -> int:
        sql = "SELECT murmurHash3_64(%(hashes)s)"
        r = self.conn.execute(sql, {"hashes": hashes})
        return int(r[0][0])

    def _insert_package(self, pkg: str, srpm_hash: int, is_srpm: bool) -> int:
        st = time.time()
        kw = {}
        hdr = self.taskfs.get_header(pkg)
        sha1 = bytes.fromhex(convert(hdr[rpmt.RPMTAG_SHA1HEADER]))
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
            if not is_srpm and ".noarch.rpm" in pkg_name:
                # XXX: workaround for multiple 'noarch' packages from different archs
                self.logger.debug(
                    f"calculate MD5, SHA256 and BLAKE2b for {pkg_name} 'noarch' package"
                )
                hashes["md5"], hashes["sha256"], hashes["blake2b"] = hashes_from_file(
                    self.taskfs.get_file_path(pkg)
                )
            else:
                if self.pkg_hashes[pkg_name].md5:
                    hashes["md5"] = self.pkg_hashes[pkg_name].md5
                else:
                    self.logger.debug(f"calculate MD5 for {pkg_name} file")
                    hashes["md5"] = md5_from_file(self.taskfs.get_file_path(pkg))

                if self.pkg_hashes[pkg_name].sha256:
                    hashes["sha256"] = self.pkg_hashes[pkg_name].sha256
                else:
                    self.logger.debug(f"calculate SHA256 for {pkg_name} file")
                    hashes["sha256"] = sha256_from_file(self.taskfs.get_file_path(pkg))

                if self.pkg_hashes[pkg_name].blake2b not in (b"", None):
                    hashes["blake2b"] = self.pkg_hashes[pkg_name].blake2b
                else:
                    self.logger.debug(f"calculate BLAKE2b for {pkg_name} file")
                    hashes["blake2b"] = blake2b_from_file(
                        self.taskfs.get_file_path(pkg)
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
    logger: logging.Logger,
    task: Task,
    num_of_workers=0,
):
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
        pkg_hashes_cache = init_cache(conn, packages_)
    else:
        pkg_hashes_cache = set()

    for _ in range(num_of_workers):
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
