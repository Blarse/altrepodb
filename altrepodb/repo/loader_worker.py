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

import logging
import threading
from typing import Iterable, Optional, Union
from pathlib import Path

from altrepodb.base import LockedIterator
from altrepodb.utils import blake2b_from_file, check_package_in_cache
from altrepodb.database import DatabaseClient

from .base import Repository
from .utils import Display
from .mapper import get_partial_pkg_map
from .package import PackageHandler, PkgHash
from .processor import RepoProcessorConfig
from .exceptions import PackageLoadError

MAX_WORKERS_FOR_SRPM = 4


class Worker(threading.Thread):
    """Package loader worker."""

    def __init__(
        self,
        connection: DatabaseClient,
        logger: logging.Logger,
        lock: threading.Lock,
        pkg_cache: set,
        src_hashes: dict[str, PkgHash],
        bin_hashes: dict[str, PkgHash],
        packages: Iterable,
        pkgset: set,
        display: Union[Display, None],
        is_src: bool = False,
        *args,
        **kwargs,
    ):
        self.connection = connection
        self.logger = logger
        self.packages = packages
        self.pkgset = pkgset
        self.display = display
        self.src_hashes = src_hashes
        self.bin_hashes = bin_hashes
        self.cache = pkg_cache
        self.is_src = is_src
        self.exc = None
        self.exc_args = None
        self.lock = lock
        self.ph = PackageHandler(connection)
        super().__init__(*args, **kwargs)

    def run(self):
        self.logger.debug("thread start")
        for package in self.packages:
            try:
                pkg_filename = Path(package).name
                header = self.ph.get_header(package)
                map_package = get_partial_pkg_map(
                    header,
                    (
                        "pkg_sourcepackage",
                        "pkg_sourcerpm",
                        "pkg_hash",
                        "pkg_arch",
                        "pkg_cs",
                    ),
                )
                kw = {
                    "pkg_filename": pkg_filename,
                    "pkg_filesize": Path(package).stat().st_size,
                }
                # add thread safety lock here
                with self.lock:
                    if self.is_src:
                        #  store pkg mmh and sha1
                        self.src_hashes[pkg_filename].sf = map_package["pkg_hash"]
                        self.src_hashes[pkg_filename].sha1 = map_package["pkg_cs"]
                        # set source rpm name and hash to self
                        kw["pkg_sourcerpm"] = pkg_filename
                        kw["pkg_srcrpm_hash"] = map_package["pkg_hash"]
                        # check if BLAKE2b hash found and if not, calculate it from file
                        if self.src_hashes[pkg_filename].blake2b in (b"", None):
                            self.logger.debug(
                                f"calculate BLAKE2b for {pkg_filename} file"
                            )
                            self.src_hashes[pkg_filename].blake2b = blake2b_from_file(
                                package
                            )
                    else:
                        #  store pkg mmh and sha1
                        self.bin_hashes[pkg_filename].sf = map_package["pkg_hash"]
                        self.bin_hashes[pkg_filename].sha1 = map_package["pkg_cs"]
                        # set source rpm name and hash
                        if map_package["pkg_sourcerpm"] in self.src_hashes:
                            kw["pkg_srcrpm_hash"] = self.src_hashes[
                                map_package["pkg_sourcerpm"]
                            ].sf
                        else:
                            kw["pkg_srcrpm_hash"] = None
                        # check if BLAKE2b hash found and if not, calculate it from file
                        if self.bin_hashes[pkg_filename].blake2b in (b"", None):
                            self.logger.debug(
                                f"calculate BLAKE2b for {pkg_filename} file"
                            )
                            self.bin_hashes[pkg_filename].blake2b = blake2b_from_file(
                                package
                            )

                # check if 'pkg_srcrpm_hash' is None - it's Ok for 'x86_64-i586'
                if (
                    map_package["pkg_arch"] == "x86_64-i586"
                    and kw["pkg_srcrpm_hash"] is None
                ):
                    kw["pkg_srcrpm_hash"] = 0

                self.logger.debug(f"processing: {package}")
                pkghash = check_package_in_cache(self.cache, map_package["pkg_hash"])

                if pkghash is None:
                    pkghash = self.ph.insert_package(header, package, **kw)
                    self.cache.add(pkghash)
                    # insert package hashes to PackageHash_buffer
                    if self.is_src:
                        self.ph.insert_pkg_hash_single(
                            self.ph.convert_hashes(self.src_hashes[pkg_filename])
                        )
                    else:
                        self.ph.insert_pkg_hash_single(
                            self.ph.convert_hashes(self.bin_hashes[pkg_filename])
                        )
                if pkghash is None:
                    raise PackageLoadError(
                        f"No hash for {package} from 'insert_package()'"
                    )
                self.pkgset.add(pkghash)
            except Exception as error:
                self.logger.error(str(error), exc_info=True)
                self.exc = error
                self.exc_args = {"package": package, "hash": pkghash}  # type: ignore
                break
            else:
                if self.display is not None:
                    self.display.inc()
        self.logger.debug("thread stop")

    def join(self):
        super().join()
        if self.exc:
            msg = (
                f"Exception occured in {self.name} for package "
                f"{self.exc_args['package']} with {self.exc_args['hash']}"  # type: ignore
            )
            raise PackageLoadError(msg) from self.exc


def package_load_worker_pool(
    repo: Repository,
    is_src: bool,
    pkgset: set,
    pkg_cache: set,
    packages_list: Iterable,
    config: RepoProcessorConfig,
    logger: Optional[logging.Logger] = None,
    display: Union[Display, None] = None,
):
    lock = threading.Lock()
    workers: list[Worker] = []
    connections: list[DatabaseClient] = []

    if logger is None:
        logger = logging.getLogger(__name__)

    packages = LockedIterator((pkg for pkg in packages_list))

    # limit workers number when dealing with SRPM to reduce
    # memory footprint while extracting spec files
    if is_src:
        num_of_workers = MAX_WORKERS_FOR_SRPM
    else:
        num_of_workers = config.workers

    for _ in range(num_of_workers):
        conn = DatabaseClient(config=config.dbconfig, logger=logger)
        connections.append(conn)
        worker = Worker(
            connection=conn,
            logger=logger,
            lock=lock,
            pkg_cache=pkg_cache,
            src_hashes=repo.src_hashes,
            bin_hashes=repo.bin_hashes,
            packages=packages,
            pkgset=pkgset,
            display=display,
            is_src=is_src,
        )
        worker.start()
        workers.append(worker)

    for w in workers:
        try:
            w.join()
        except PackageLoadError as e:
            logger.error(f"Error: {e.message}")
            raise e

    for c in connections:
        if c is not None:
            c.disconnect()
