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
from pathlib import Path

from altrepodb.database import DatabaseClient
from altrepodb.logger import LoggerProtocol
from altrepodb.utils import Display, update_dictionary_with

from .base import Repository
from .processor import RepoProcessorConfig
from .exceptions import RepoProcessingError
from .packageset import PackageSetHandler
from .loader_helper import RepoLoadHelper
from .loader_worker import package_load_worker_pool


class RepoLoadHandler:
    """Handles repository structure loading to DB."""

    def __init__(self, config: RepoProcessorConfig, logger: LoggerProtocol) -> None:
        self.config = config
        self.logger = logger
        self.cache = set()
        self.repo : Repository
        self.conn = DatabaseClient(config=self.config.dbconfig, logger=self.logger)
        self.rlh = RepoLoadHelper(conn=self.conn, logger=self.logger)
        self.psh = PackageSetHandler(conn=self.conn, logger=self.logger)

        self.display = None
        if self.config.verbose:
            self.display = Display(log=self.logger)


    def check_repo_in_db(self):
        if self.rlh.check_repo_date_name_in_db(self.config.name, self.config.date.date()):
            if not self.config.force:
                self.logger.error(
                    f"Repository with name '{self.config.name}' and "
                    f"date '{self.config.date.date()}' already exists in database"
                )
                raise RepoProcessingError("Package set is already loaded to DB!")

    def _init_cache(self):
        self.rlh.init_hash_temp_table(self.repo.src_hashes)
        self.rlh.init_hash_temp_table(self.repo.bin_hashes)
        self.rlh.update_hases_from_db(self.repo.src_hashes)
        self.rlh.update_hases_from_db(self.repo.bin_hashes)
        self.cache = self.rlh.init_cache(self.repo.src_hashes, self.repo.bin_hashes)

    def _load_srpms(self):
        # level 1 : src
        # load source RPMs first
        # generate 'src.rpm' packages list
        ts = time.time()
        pkg_count = 0
        pkg_count2 = 0
        pkgset = set()
        pkgset_cached = set()
        packages_list = []
        self.logger.info("Start checking SRC packages")
        # load source packages fom 'files/SRPMS'
        src_dir = Path(self.config.path).joinpath("files/SRPMS")
        if not src_dir.is_dir():
            raise RepoProcessingError(f"'/files/SRPMS' directory not found")
        self.logger.info(f"Start checking SRC packages in {'/'.join(src_dir.parts[-2:])}")
        for pkg in self.repo.src_hashes:
            pkg_count += 1
            if self.repo.src_hashes[pkg].sha1 is None:
                rpm_file = src_dir.joinpath(pkg)
                if not rpm_file.is_file():
                    raise RepoProcessingError(f"File {rpm_file} not found")
                packages_list.append(str(rpm_file))
            else:
                pkgh = self.repo.src_hashes[pkg].sf
                if not pkgh:
                    raise RepoProcessingError(f"No hash found in cache for {pkg}")
                pkgset_cached.add(pkgh)
                pkg_count2 += 1
        self.logger.info(
            f"Checked {pkg_count} SRC packages. "
            f"{pkg_count2} packages in cache, "
            f"{len(packages_list)} packages for load. "
            f"Time elapsed {(time.time() - ts):.3f} sec."
        )
        # load 'src.rpm' packages
        package_load_worker_pool(
            is_src=True,
            repo=self.repo,
            pkgset=pkgset,
            pkg_cache=self.cache,
            packages_list=packages_list,
            config=self.config,
            logger=self.logger,
            display=self.display,
        )
        # build pkgset for PackageSet record
        pkgset.update(pkgset_cached)

        self.psh.insert_pkgset(self.repo.src.uuid, pkgset)
        # store PackageSetName record for 'src'
        tmp_d = {"depth": "1", "type": "srpm", "size": str(len(pkgset))}
        tmp_d = update_dictionary_with(tmp_d, self.repo.root.kwargs["class"], "class")
        tmp_d = update_dictionary_with(tmp_d, self.repo.src.path, "SRPMS")
        tmp_d = update_dictionary_with(tmp_d, self.repo.root.name, "repo")
        self.psh.insert_pkgset_name(
            name=self.repo.src.name,
            uuid=self.repo.src.uuid,
            puuid=self.repo.src.puuid,
            ruuid=self.repo.root.uuid,
            depth=1,
            tag=self.config.tag,
            date=self.config.date,
            complete=1,
            kw_args=tmp_d,
        )

    def _load_architectures(self):
        for arch in self.repo.archs:
            tmp_d = {"depth": "1", "type": "arch", "size": "0"}
            tmp_d = update_dictionary_with(tmp_d, self.repo.root.kwargs["class"], "class")
            tmp_d = update_dictionary_with(tmp_d, arch.path, "path")
            tmp_d = update_dictionary_with(tmp_d, self.repo.root.name, "repo")
            self.psh.insert_pkgset_name(
                name=arch.name,
                uuid=arch.uuid,
                puuid=arch.puuid,
                ruuid=self.repo.root.uuid,
                depth=1,
                tag=self.config.tag,
                date=self.config.date,
                complete=1,
                kw_args=tmp_d,
            )

    def _load_components(self):
        for comp in self.repo.comps:
            # load RPMs first
            ts = time.time()
            pkg_count = 0
            pkgset = set()
            pkgset_cached = set()
            packages_list = []
            # generate 'rpm' packages list
            self.logger.info(f"Start checking RPM packages in '{comp.path}'")
            rpm_dir = Path(self.config.path).joinpath(comp.path)
            # proceed binary packages using repo["bin_pkgs"] dictionary
            arch_ = comp.path.split("/")[0]
            comp_ = comp.path.split(".")[-1]
            for pkg in self.repo.bin_pkgs[(arch_, comp_)]:
                rpm_file = rpm_dir.joinpath(pkg)
                pkg_count += 1
                if self.repo.bin_hashes[pkg].sha1 is None:
                    if not rpm_file.is_file():
                        raise ValueError(f"File {pkg} not found in {comp.path}")
                    packages_list.append(str(rpm_file))
                else:
                    pkgh = self.repo.bin_hashes[rpm_file.name].sf
                    if not pkgh:
                        raise ValueError(f"No hash found in cache for {pkg}")
                    pkgset_cached.add(pkgh)
            self.logger.info(
                f"Checked {pkg_count} RPM packages. "
                f"{len(packages_list)} packages for load. "
                f"Time elapsed {(time.time() - ts):.3f} sec."
            )
            # load '.rpm' packages
            package_load_worker_pool(
                is_src=False,
                repo=self.repo,
                pkgset=pkgset,
                pkg_cache=self.cache,
                packages_list=packages_list,
                config=self.config,
                logger=self.logger,
                display=self.display,
            )
            # build pkgset for PackageSet record
            pkgset.update(pkgset_cached)

            self.psh.insert_pkgset(comp.uuid, pkgset)
            # store PackageSetName record
            tmp_d = {"depth": "2", "type": "comp", "size": str(len(pkgset))}
            tmp_d = update_dictionary_with(tmp_d, self.repo.root.kwargs["class"], "class")
            tmp_d = update_dictionary_with(tmp_d, comp.path, "path")
            tmp_d = update_dictionary_with(tmp_d, self.repo.root.name, "repo")
            self.psh.insert_pkgset_name(
                name=comp.name,
                uuid=comp.uuid,
                puuid=comp.puuid,
                ruuid=self.repo.root.uuid,
                depth=2,
                tag=self.config.tag,
                date=self.config.date,
                complete=1,
                kw_args=tmp_d,
            )

    def _load_root(self):
        tmp_d = {
            "depth": "0",
            "type": "repo",
            "size": str(len(self.repo.src_hashes) + len(self.repo.bin_hashes)),
        }
        tmp_d = update_dictionary_with(tmp_d, self.repo.root.kwargs, None)
        tmp_d = update_dictionary_with(tmp_d, list(self.repo.all_archs), "archs")
        tmp_d = update_dictionary_with(tmp_d, list(self.repo.all_comps), "comps")
        self.psh.insert_pkgset_name(
            name=self.repo.root.name,
            uuid=self.repo.root.uuid,
            puuid=self.repo.root.puuid,
            ruuid=self.repo.root.uuid,
            depth=0,
            tag=self.config.tag,
            date=self.config.date,
            complete=1,
            kw_args=tmp_d,
        )

    def upload(self, repo: Repository):
        self.repo = repo
        try:
            self._init_cache()
            self._load_srpms()
            self._load_architectures()
            self._load_components()
            self._load_root()
            if self.display is not None:
                self.display.conclusion()
        except Exception as e:
            raise e
        finally:
            self.conn.disconnect()
