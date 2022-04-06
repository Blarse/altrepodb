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

import sys
import json
import argparse
import configparser
from typing import Any
from pathlib import Path
from dataclasses import dataclass
from collections import namedtuple

from altrepodb.utils import run_command, RunCommandError
from altrepodb.logger import LoggerProtocol, LoggerLevel, get_config_logger
from altrepodb.database import DatabaseClient, DatabaseConfig, DatabaseError

NAME = "spdx"
SPDX_URL = "https://github.com/spdx/license-list-data"
SPDX_GIT_ROOT = "SPDX"
SPDX_LICENSES = "json/details"
SPDX_EXCEPTIONS = "json/exceptions"
SPDX_GIT_TIMEOUT = 60


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
    logger: LoggerProtocol
    dbconfig: DatabaseConfig
    timeout: int = 30


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
        self.spdx_root = Path.cwd().joinpath(SPDX_GIT_ROOT)
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
            raise SPDXError(f"Failed to update SPDX git repository") from e
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
                        spdx_type="license"
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
                        spdx_type="exception"
                    )
                )

        return updated

    def _save_to_db(self, data: list[DBLicense]) -> None:
        try:
            res = self.conn.execute(self.sql.insert_spdx, data)
        except Exception as exc:
            if issubclass(exc.__class__, (DatabaseError,)):
                raise SPDXError("Failed load data to database") from exc
            raise exc

    def run(self) -> None:
        try:
            self.logger.info(f"Check SPDX for updates")
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


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database password")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    args = parser.parse_args()

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


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_config_logger(
        NAME,
        tag="load",
        config=args.config,
    )
    if args.debug:
        logger.setLevel(LoggerLevel.DEBUG)
    logger.debug(f"Run with args: {args}")
    try:
        rp = SPDX(
            SPDXConfig(
                url=SPDX_URL,
                logger=logger,
                dbconfig=DatabaseConfig(
                    host=args.host,
                    port=args.port,
                    name=args.dbname,
                    user=args.user,
                    password=args.password,
                ),
                timeout=SPDX_GIT_TIMEOUT,
            )
        )
        rp.run()

    except Exception as error:
        logger.error(
            f"Error occurred while processing licenses from SPDX: {error}",
            exc_info=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
