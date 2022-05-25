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

import json
from pathlib import Path
from logging import Logger
from dataclasses import dataclass
from collections import namedtuple

from .utils import run_command, RunCommandError
from .database import DatabaseClient, DatabaseConfig, DatabaseError

SPDX_URL = "https://github.com/spdx/license-list-data"
SPDX_GIT_ROOT = "SPDX"
SPDX_LICENSES = "json/details"
SPDX_EXCEPTIONS = "json/exceptions"
SPDX_GIT_TIMEOUT = 60 * 5


class SPDXError(Exception):
    pass


@dataclass(frozen=True)
class SQL:
    get_spdx = """
SELECT
    spdx_id,
    spdx_name,
    spdx_text,
    spdx_header,
    spdx_urls,
    spdx_type
FROM SPDXLicenses
"""

    insert_spdx = """
INSERT INTO SPDXLicenses (*) VALUES
"""


@dataclass
class SPDXConfig:
    url: str
    logger: Logger
    dbconfig: DatabaseConfig
    timeout: int = 30
    git_root: str = ""


@dataclass(frozen=True)
class License:
    id: str
    name: str
    text: str
    header: str
    urls: list[str]


DBLicense = namedtuple(
    "DBLicense",
    [
        "spdx_id",
        "spdx_name",
        "spdx_text",
        "spdx_header",
        "spdx_urls",
        "spdx_type",
    ],
)


class SPDX:
    def __init__(self, config: SPDXConfig) -> None:
        self.sql = SQL()
        self.url = config.url
        self.conn = self.conn = DatabaseClient(
            config=config.dbconfig,
            logger=config.logger,
        )
        self.logger = config.logger
        self.timeout = config.timeout
        if not config.git_root:
            self.spdx_root = Path.cwd().joinpath(SPDX_GIT_ROOT)
        else:
            self.spdx_root = Path(config.git_root)
        self._licenses: list[License] = []
        self._exceptions: list[License] = []

    def _update_spdx_git(self) -> None:
        use_git_pull = False
        if self.spdx_root.exists():
            if not self.spdx_root.is_dir():
                raise SPDXError(f"{str(self.spdx_root)} exists and not a directory")
            use_git_pull = True
        else:
            try:
                self.spdx_root.mkdir(mode=0o755)
            except OSError:
                raise SPDXError("Failed to create SPDX git directory")
        self.logger.info("Updating SPDX git repository")
        try:
            if use_git_pull:
                self.logger.debug("Pull SPDX git master")
                _, _, _, _ = run_command(
                    *[
                        "git",
                        f"--git-dir={str(self.spdx_root.joinpath('.git'))}",
                        "pull",
                        "origin",
                        "master",
                    ],
                    raise_on_error=True,
                    logger=self.logger,
                    timeout=self.timeout,
                )
            else:
                self.logger.debug("Clone SPDX git master")
                _, _, _, _ = run_command(
                    *["git", "clone", "--depth=1", SPDX_URL, str(self.spdx_root)],
                    raise_on_error=True,
                    logger=self.logger,
                    timeout=self.timeout,
                )
        except RunCommandError as e:
            raise SPDXError("Failed to update SPDX git repository") from e
        self.logger.info("SPDX git repository is up to date")

    def _collect_licenses(self):
        # loop over licenses in cloned SPDX git
        for license_file in (
            f
            for f in self.spdx_root.joinpath(SPDX_LICENSES).iterdir()
            if f.is_file() and ".json" in f.name
        ):
            with open(license_file) as f:
                license = json.load(f)
                self._licenses.append(
                    License(
                        id=license["licenseId"],
                        name=license["name"],
                        text=license["licenseText"],
                        header=license.get("standardLicenseHeader", ""),
                        urls=license["seeAlso"],
                    )
                )

    def _collect_license_exceptions(self):
        # loop over license exceptions in cloned SPDX git
        for license_file in (
            f
            for f in self.spdx_root.joinpath(SPDX_EXCEPTIONS).iterdir()
            if f.is_file() and ".json" in f.name
        ):
            with open(license_file) as f:
                license = json.load(f)
                self._exceptions.append(
                    License(
                        id=license["licenseExceptionId"],
                        name=license["name"],
                        text=license["licenseExceptionText"],
                        header=license.get("licenseComments", ""),
                        urls=license["seeAlso"],
                    )
                )

    def _check_for_updates(self) -> list[DBLicense]:
        db_licenses: list[License] = []
        db_exceptions: list[License] = []
        updated: list[DBLicense] = []

        try:
            res = self.conn.execute(self.sql.get_spdx)
        except Exception as exc:
            if issubclass(exc.__class__, (DatabaseError,)):
                raise SPDXError("Failed get data from database") from exc
            raise exc
        if res:
            for el in res:
                if el[-1] == "license":
                    db_licenses.append(License(*el[:-1]))
                elif el[-1] == "exception":
                    db_exceptions.append(License(*el[:-1]))
                else:
                    raise SPDXError("Inconsistent data from DB")

        for license in self._licenses:
            if license not in db_licenses:
                updated.append(
                    DBLicense(
                        spdx_id=license.id,
                        spdx_name=license.name,
                        spdx_text=license.text,
                        spdx_header=license.header,
                        spdx_urls=license.urls,
                        spdx_type="license",
                    )
                )

        for exception in self._exceptions:
            if exception not in db_exceptions:
                updated.append(
                    DBLicense(
                        spdx_id=exception.id,
                        spdx_name=exception.name,
                        spdx_text=exception.text,
                        spdx_header=exception.header,
                        spdx_urls=exception.urls,
                        spdx_type="exception",
                    )
                )

        return updated

    def _save_to_db(self, data: list[DBLicense]) -> None:
        try:
            _ = self.conn.execute(self.sql.insert_spdx, data)
        except Exception as exc:
            if issubclass(exc.__class__, (DatabaseError,)):
                raise SPDXError("Failed load data to database") from exc
            raise exc

    def run(self) -> None:
        try:
            self.logger.info("Check SPDX for updates")
            self._update_spdx_git()
            self._collect_licenses()
            self._collect_license_exceptions()
            updated = self._check_for_updates()
            if updated:
                self.logger.info("Loading new SPDX data to database...")
                self._save_to_db(updated)
                self.logger.info("SPDX data loaded to database")
            else:
                self.logger.info("SPDX data is up-to-date")
        except Exception as e:
            self.logger.error("Error occured while processing SPDX data")
            raise SPDXError from e
        finally:
            self.conn.disconnect()
