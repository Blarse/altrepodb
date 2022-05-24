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
import traceback
from pathlib import Path
from typing import Iterator

from altrpm import rpm as rpmt

from altrepodb.base import LockedIterator, RaisingTread, PkgHash
from altrepodb.exceptions import RaisingThreadError
from altrepodb.utils import (
    md5_from_file,
    sha256_from_file,
    blake2b_from_file,
    check_package_in_cache,
)
from altrepodb.database import DatabaseClient
from altrepodb.repo.utils import convert
from altrepodb.repo.mapper import snowflake_id_pkg
from altrepodb.repo.package import PackageHandler

from .base import Task, TaskProcessorConfig
from .reader import TaskFromFileSystem
from .utils import init_cache


class PackageLoaderWorker(RaisingTread):
    def __init__(
        self,
        conn: DatabaseClient,
        taskfs: TaskFromFileSystem,
        logger: logging.Logger,
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
        self.ph = PackageHandler(conn=conn)
        super().__init__(*args, **kwargs)

    def _insert_package(self, pkg, srpm_hash, is_srpm):
        st = time.time()
        kw = {}
        hdr = self.taskfs.get_header(pkg)
        sha1 = bytes.fromhex(convert(hdr[rpmt.RPMTAG_SHA1HEADER]))
        hashes = {"sha1": sha1, "mmh": snowflake_id_pkg(hdr)}
        pkg_name = Path(pkg).name

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
            hashes["blake2b"] = blake2b_from_file(self.taskfs.get_file_path(pkg))

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
    logger: logging.Logger,
    task: Task,
    num_of_workers: int = 0,
    loaded_from="",
):
    st = time.time()
    workers: list[RaisingTread] = []
    pkg_count: list[int] = []
    connections: list[DatabaseClient] = []
    packages: Iterator[str] = LockedIterator((pkg for pkg in task.arepo))  # type: ignore

    if not conf.force:
        pkg_hashes_cache = init_cache(conn, task.arepo)
    else:
        pkg_hashes_cache = set()

    if not num_of_workers:
        num_of_workers = conf.workers

    for _ in range(num_of_workers):
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
