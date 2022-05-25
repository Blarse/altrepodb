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
import requests
import datetime
from dataclasses import dataclass
from requests import HTTPError
from typing import Optional, NamedTuple, Any
from enum import Enum

from .utils import cvt_datetime_local_to_utc, cvt_ts_to_datetime
from .htmllistparse import fetch_listing
from .database import DatabaseConfig, DatabaseClient


class EndpointType(Enum):
    DIR = 1
    FILE1 = 2
    FILE2 = 3


class Endpoint(NamedTuple):
    name: str
    type: EndpointType
    path_prefix: str
    path_suffix: str
    destination: Optional[str] = None


class Target(NamedTuple):
    branch: str
    arch: str
    name: str
    type: EndpointType
    url: str
    destination: Optional[str]


class Package(NamedTuple):
    name: str
    version: str
    release: str


class PackageInfo(NamedTuple):
    package: Package
    modified: datetime.datetime
    size: int


class FileInfo(NamedTuple):
    name: str
    modified: datetime.datetime
    size: int


class TargetKey(NamedTuple):
    branch: str
    arch: str
    name: str


# BEEHIVE_BASE_URL = "https://git.altlinux.org/beehive"
# BEEHIVE_BRANCHES = (
#     "Sisyphus",
#     "p10",
#     "p9",
# )
# BEEHIVE_ARCHS = ("i586", "x86_64")
# BEEHIVE_ENDPOINTS = (
#     Endpoint("latest_dir_mtime", EPType.DIR, "logs", "", "latest"),
#     Endpoint("time_file_listing", EPType.FILE1, "logs", "latest/time.list", None),
#     Endpoint("error_dir_listing", EPType.DIR, "logs", "latest/error", None),
#     Endpoint("success_dir_listing", EPType.DIR, "logs", "latest/success", None),
#     Endpoint("ftbfs_since_file_listing", EPType.FILE2, "stats", "ftbfs-since", None),
# )


class BeehiveLoadError(Exception):
    pass


@dataclass(frozen=True)
class SQL:
    get_pkgset_packages = """
WITH
(
    SELECT pkgset_uuid
    FROM PackageSetName
    WHERE pkgset_nodename = 'srpm'
        AND pkgset_ruuid IN
    (
        SELECT pkgset_uuid
        FROM PackageSetName
        WHERE pkgset_depth = 0
            AND pkgset_nodename = %(branch)s
            AND pkgset_date = %(date)s
    )
) AS src_uuid
SELECT
    pkg_hash,
    pkg_name,
    pkg_version,
    pkg_release
FROM Packages
WHERE pkg_sourcepackage = 1
    AND pkg_hash IN
    (
        SELECT pkg_hash
        FROM PackageSet
        WHERE pkgset_uuid = src_uuid
    )
"""

    get_recent_pkgset_date = """
SELECT * FROM
(
    SELECT max(pkgset_date) AS date
    FROM PackageSetName
    WHERE pkgset_nodename = %(branch)s
        AND pkgset_date < %(date)s
)
WHERE date > '2000-01-01'
"""

    get_all_packages_versions = """
WITH
    pkg_packages AS
    (
        SELECT
            pkg_hash,
            pkg_name,
            pkg_version,
            pkg_release
        FROM Packages
        WHERE (pkg_name IN %(packages)s) AND (pkg_sourcepackage = 1)
    ),
    pkg_tasks AS
    (
        SELECT DISTINCT
            task_id,
            titer_srcrpm_hash
        FROM TaskIterations
        WHERE titer_srcrpm_hash IN (
            SELECT pkg_hash
            FROM pkg_packages
        )
    )
SELECT DISTINCT
    pkg_tasks.task_id,
    pkg_tasks.titer_srcrpm_hash,
    TSK.task_repo,
    PKG.*
FROM pkg_tasks
LEFT JOIN
(
    SELECT
        task_id,
        task_repo
    FROM Tasks
) AS TSK ON TSK.task_id = pkg_tasks.task_id
LEFT JOIN
(
    SELECT *
    FROM pkg_packages
) AS PKG ON pkg_hash = titer_srcrpm_hash
WHERE TSK.task_repo = %(branch)s
ORDER BY pkg_tasks.task_id ASC
"""

    get_last_beehive_changed = """
SELECT
    pkgset_name,
    bh_arch,
    max(bh_updated)
FROM BeehiveStatus
GROUP BY
    pkgset_name,
    bh_arch
"""

    insert_into_beehive_status = """
INSERT INTO BeehiveStatus (*) VALUES
"""


@dataclass
class BeehiveConfig:
    base_url: str
    archs: tuple[str, ...]
    branches: tuple[str, ...]
    logger: logging.Logger
    dbconfig: DatabaseConfig
    endpoints: tuple[Endpoint, ...]
    timeout: int = 30


class Beehive:
    def __init__(self, config: BeehiveConfig) -> None:
        self.base_url = config.base_url
        self.branches = config.branches
        self.archs = config.archs
        self.sql = SQL()
        self.conn = DatabaseClient(
            config=config.dbconfig,
            logger=config.logger,
        )
        self.logger = config.logger
        self.timeout = config.timeout
        self.endpoints = config.endpoints
        self.targets = self._build_beehive_targets_list()
        self.beehive: dict[TargetKey, list[Any]] = {}

    @staticmethod
    def _parse_name_evr(pkg: str) -> Package:
        """Parse package file name to Package(name, version, release)."""

        if pkg.endswith(".src.rpm"):
            pkg = pkg.replace(".src.rpm", "")
        evr = pkg.split("-")[-2:]
        if len(evr) == 2 and evr[1].startswith("alt"):
            version, release = evr
        else:
            version = release = ""
        #  delete epoch from version
        if ":" in version:
            version_ = version.split(":")[1]
        else:
            version_ = version
        name = pkg.replace(f"-{version}-{release}", "")
        return Package(name, version_, release)

    def _build_beehive_targets_list(self) -> list[Target]:
        targets = []
        for branch in self.branches:
            for arch in self.archs:
                for endpoint in self.endpoints:
                    url = "/".join(
                        (
                            self.base_url,
                            endpoint.path_prefix,
                            branch,
                            arch,
                            endpoint.path_suffix,
                        )
                    )
                    targets.append(
                        Target(
                            branch,
                            arch,
                            endpoint.name,
                            endpoint.type,
                            url,
                            endpoint.destination,
                        )
                    )
        return targets

    def _get_content(self, target: Target) -> tuple[Target, Any]:
        def process_package_listing_item(x):
            return PackageInfo(
                self._parse_name_evr(x.name),
                datetime.datetime(*x.modified[0:6]),
                x.size,
            )

        def process_file_listing_item(x):
            return FileInfo(x.name, datetime.datetime(*x.modified[0:6]), x.size)

        try:
            destination = target.destination
            if target.type == EndpointType.FILE1:
                response = requests.get(target.url, timeout=self.timeout)
                response.raise_for_status()
                # return parsed file contents
                packages: list[tuple[Package, float]] = []
                for line in response.text.splitlines():
                    line_context = line.split("\t")[:2]
                    packages.append(
                        (self._parse_name_evr(line_context[0]), float(line_context[1]))
                    )
                return target, packages
            if target.type == EndpointType.FILE2:
                response = requests.get(target.url, timeout=self.timeout)
                response.raise_for_status()
                # return parsed file contents
                packages: list[tuple[Package, float]] = []
                for line in response.text.splitlines():
                    line_context = line.split("\t")[:2]
                    packages.append(
                        (self._parse_name_evr(line_context[0]), int(line_context[1]))
                    )
                return target, packages
            elif target.type == EndpointType.DIR:
                _, listing = fetch_listing(target.url, timeout=self.timeout)
                if destination:
                    matches: list[FileInfo] = []
                    if isinstance(destination, str):
                        for file_ in listing:
                            if file_.name == destination:
                                matches.append(process_file_listing_item(file_))
                                break
                    if isinstance(destination, (list, tuple)):
                        for file_ in listing:
                            if file_.name in destination:
                                matches.append(process_file_listing_item(file_))
                    return target, matches
                else:
                    files = [process_package_listing_item(f) for f in listing]
                    return target, files
            else:
                raise ValueError(f"Unknown target type {target.type}")
        except Exception as e:
            if issubclass(e.__class__, HTTPError):
                self.logger.warning(f"Failed to get data from URL: {target.url}")
                return target, []
            else:
                raise e

    def _get_beehive_build_status(
        self, t_key: TargetKey, result_type: str
    ) -> set[Package]:
        if result_type == "error":
            t_key = t_key._replace(name="error_dir_listing")
        elif result_type == "success":
            t_key = t_key._replace(name="success_dir_listing")
        else:
            raise ValueError(f"Unknown result_type {result_type}")

        if t_key not in self.beehive:
            self.logger.error("Target not found in Beehive")
            raise ValueError(f"Wrong target key {t_key}")

        return {el[0] for el in self.beehive[t_key]}

    def _get_beehive_build_time(self, t_key: TargetKey) -> dict[Package, float]:
        if t_key not in self.beehive:
            self.logger.error("Target not found in Beehive")
            raise ValueError(f"Wrong target key {t_key}")

        return {el[0]: el[1] for el in self.beehive[t_key]}

    def _get_beehive_ftbfs_since(self, t_key: TargetKey) -> dict[Package, int]:
        t_key = t_key._replace(name="ftbfs_since_file_listing")

        if t_key not in self.beehive:
            self.logger.error("Target not found in Beehive")
            raise ValueError(f"Wrong target key {t_key}")

        return {el[0]: el[1] for el in self.beehive[t_key]}

    def _get_latest_mtime(self, t_key: TargetKey) -> datetime.datetime:
        t_key = t_key._replace(name="latest_dir_mtime")
        mtime = self.beehive[t_key][0].modified.replace(
            hour=12, minute=0, second=0, microsecond=0
        )
        return mtime

    def _get_last_beehive_status_from_db(
        self,
    ) -> dict[tuple[str, str], datetime.datetime]:
        self.logger.info("Fetching latest Beehive results loaded to DB")
        res = self.conn.execute(self.sql.get_last_beehive_changed)
        last_bh_updated = {(el[0], el[1]): el[2] for el in res}  # type: ignore
        return last_bh_updated

    def _get_packages_from_db(self, t_key: TargetKey) -> dict[Package, int]:
        modified = self._get_latest_mtime(t_key)

        self.logger.info(
            f"Fetching packages for {t_key.branch} on date {modified} from DB"
        )
        sql_res = self.conn.execute(
            self.sql.get_pkgset_packages,
            params={"branch": t_key.branch, "date": modified},
        )

        packages_from_db = {Package(*el[1:]): int(el[0]) for el in sql_res}  # type: ignore

        if not packages_from_db:
            self.logger.info(
                f"No data found in DB for {t_key.branch} on date {modified}"
            )
            # try to find and load the latest repository state prior to Beehive date
            self.logger.info(f"Fetching recent loaded date for {t_key.branch} from DB")
            sql_res = self.conn.execute(
                self.sql.get_recent_pkgset_date,
                params={"branch": t_key.branch, "date": modified},
            )
            if not sql_res:
                self.logger.error(
                    f"Failed to find recent lodaded date for {t_key.branch} in DB"
                )
                return {}
            modified = sql_res[0][0]  # type: ignore
            # load packages from recent repository state
            self.logger.info(
                f"Fetching packages for {t_key.branch} on date {modified} from DB"
            )
            sql_res = self.conn.execute(
                self.sql.get_pkgset_packages,
                params={"branch": t_key.branch, "date": modified},
            )

            packages_from_db = {Package(*el[1:]): int(el[0]) for el in sql_res}  # type: ignore

        return packages_from_db

    def _get_missing_packages_infor_from_db(
        self, t_key: TargetKey, packages: list[Package]
    ) -> dict[Package, int]:
        branch = t_key.branch
        #  convert list of packages to set for fast searching
        packages_ = set(packages)
        self.logger.info("Fetching packages info from DB")
        sql_res = self.conn.execute(
            self.sql.get_all_packages_versions,
            params={"packages": [pkg.name for pkg in packages_], "branch": branch},
        )

        if not sql_res:
            self.logger.error(f"No data found in DB for {packages_}")
            return {}
        self.logger.info(f"Found {len(sql_res)} packages from DB")  # type: ignore

        res = {}
        for hsh, pkg in {(int(el[3]), Package(*el[4:])) for el in sql_res}:  # type: ignore
            if pkg in packages_:
                res[pkg] = hsh

        return res

    def _compare_beehive_with_db(
        self,
        t_key: TargetKey,
        packages_from_beehive: dict[Package, Any],
        packages_from_db: dict[Package, Any],
    ) -> tuple[list[Package], list[Package]]:
        pkgs_from_db = set(packages_from_db.keys())
        pkgs_from_beehive = set(packages_from_beehive.keys())

        if not packages_from_db:
            self.logger.info("Empty 'packages_from_db' list. Exiting..")
            return [], []

        if not pkgs_from_beehive:
            self.logger.info("Empty 'pkgs_from_beehive' list. Exiting..")
            return [], []

        pkgs_missing = []
        for pkg in pkgs_from_db:
            if pkg not in pkgs_from_beehive:
                pkgs_missing.append(pkg)
        self.logger.info(
            f"{len(pkgs_missing)} packages from DB are not in {t_key.branch}/{t_key.arch} files from Beehive"
        )

        mismatched_packages = []
        not_found_packages = []
        self.logger.info("Check packages from beehive that are not in DB")
        for pkg in pkgs_from_beehive:
            if pkg not in pkgs_from_db:
                self.logger.debug(f"Package {pkg} not found in DB")
                name_matched = False
                for pkg2 in pkgs_from_db:
                    if pkg2.name == pkg.name:
                        self.logger.debug(
                            f"Missing package name matched: Beehive: {pkg} DB: {pkg2}"
                        )
                        mismatched_packages.append(pkg)
                        name_matched = True
                        break
                if not name_matched:
                    self.logger.debug(
                        f"Package {pkg} from Beehive not found in packages from DB"
                    )
                    not_found_packages.append(pkg)

        return mismatched_packages, not_found_packages

    def _store_beehive_results(
        self,
        t_key: TargetKey,
        pkgs_time: dict[Package, float],
        pkgs_success: set[Package],
        pkgs_error: set[Package],
        pkgs_from_db: dict[Package, int],
        pkgs_ftbfs: dict[Package, int],
    ) -> None:
        mtime = self._get_latest_mtime(t_key)
        result = []
        for pkg, b_time in pkgs_time.items():
            el_dict = {
                "pkg_hash": None,
                "pkg_name": pkg.name,
                "pkg_version": pkg.version,
                "pkg_release": pkg.release,
                "pkgset_name": t_key.branch,
                "bh_arch": t_key.arch,
                "bh_status": None,
                "bh_build_time": b_time,
                "bh_updated": cvt_datetime_local_to_utc(mtime),
            }

            if pkg in pkgs_success:
                el_dict["bh_status"] = "success"
                el_dict["bh_ftbfs_since"] = el_dict["bh_updated"]
            elif pkg in pkgs_error:
                el_dict["bh_status"] = "error"
                pkg_ = pkg._replace(version="", release="")
                if pkg_ in pkgs_ftbfs:
                    el_dict["bh_ftbfs_since"] = cvt_ts_to_datetime(pkgs_ftbfs[pkg_])
                else:
                    el_dict["bh_ftbfs_since"] = el_dict["bh_updated"]
            else:
                self.logger.error(
                    f"Failed to get status for package {pkg}. Element: {el_dict}"
                )
                raise ValueError("Can't find package build status")

            try:
                el_dict["pkg_hash"] = pkgs_from_db[pkg]
            except KeyError:
                self.logger.error(
                    f"Failed to get hash for package {pkg}. Element: {el_dict}"
                )
                raise ValueError("Can't find package hash")

            result.append(el_dict)

        self.conn.execute(self.sql.insert_into_beehive_status, result)
        self.logger.info(
            f"Data for {t_key.branch}/{t_key.arch} on {mtime} inserted to DB"
        )

    def store(self) -> None:
        latest_beehive_from_db = self._get_last_beehive_status_from_db()
        for branch_ in self.branches:
            branch = branch_.lower()
            for arch in self.archs:
                t_key = TargetKey(branch, arch, "time_file_listing")
                # check if target contents were loaded from Beehive
                if t_key not in self.beehive:
                    continue

                self.logger.info(f"Processing data for {branch_}/{arch}")
                pkgs_time = self._get_beehive_build_time(t_key)

                # check if beehive result already loaded to DB
                mtime = self._get_latest_mtime(t_key)
                mtime_from_db = latest_beehive_from_db.get((branch, arch), None)
                if mtime == mtime_from_db:
                    self.logger.info(
                        f"Data for {branch_}/{arch} on {mtime} already loaded to DB"
                    )
                    continue

                if not pkgs_time:
                    self.logger.error(
                        f"No package build time info found from Beehive for {branch_}/{arch}"
                    )
                    raise ValueError("No data found from Beehive")
                    # continue
                self.logger.info(f"Found {len(pkgs_time)} packages from Beehive")

                pkgs_from_db = self._get_packages_from_db(t_key)
                if not pkgs_from_db:
                    self.logger.warning(
                        f"No packages info loaded from DB. Skip processing data for {branch_}/{arch}"
                    )
                    continue
                self.logger.info(f"Found {len(pkgs_from_db)} packages from DB")

                miss, nf = self._compare_beehive_with_db(t_key, pkgs_time, pkgs_from_db)
                self.logger.debug(f"Missmatched packages: {miss}")
                self.logger.debug(f"Not found packages: {nf}")

                if miss + nf:
                    res = self._get_missing_packages_infor_from_db(
                        t_key=t_key, packages=(miss + nf)
                    )
                    pkgs_from_db.update(res)

                if len(pkgs_time) > len(pkgs_from_db):
                    self.logger.error(
                        f"Inconsistent data from Beehive and form DB for {branch_}/{arch}"
                    )
                    break

                pkgs_success = self._get_beehive_build_status(
                    t_key=t_key, result_type="success"
                )
                pkgs_error = self._get_beehive_build_status(
                    t_key=t_key, result_type="error"
                )
                pkgs_status = pkgs_success | pkgs_error

                pkgs_ftbfs = self._get_beehive_ftbfs_since(t_key=t_key)

                if len(pkgs_time) != len(pkgs_status):
                    self.logger.error(
                        f"Inconsistent data from Beehive for {branch_}/{arch}"
                    )
                    break

                self._store_beehive_results(
                    t_key, pkgs_time, pkgs_success, pkgs_error, pkgs_from_db, pkgs_ftbfs
                )

    def load(self) -> None:
        for target in self.targets:
            self.logger.info(f"Fetching data from {target.url}")
            target, result = self._get_content(target)
            key = TargetKey(target.branch.lower(), target.arch, target.name)
            if result:
                self.beehive[key] = result

    def run(self) -> None:
        try:
            self.load()
            self.store()
        except Exception as e:
            self.logger.error(f"Error occured while processing Beehive data: {e}")
            raise BeehiveLoadError from e
        finally:
            self.conn.disconnect()
