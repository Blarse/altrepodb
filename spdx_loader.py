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
    get_last_date = """
SELECT max(rc_test_date) FROM PackagesRepocop
"""

    insert_repocop = """
INSERT INTO PackagesRepocop (*) VALUES
"""


@dataclass
class SPDXConfig:
    url: str
    logger: LoggerProtocol
    dbconfig: DatabaseConfig
    timeout: int = 30


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
                        # "--git-dir",
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
                    *[
                        "git",
                        "clone",
                        "--depth=1",
                        SPDX_URL,
                        str(self.spdx_root)
                    ],
                    raise_on_error=True,
                    logger=self.logger,
                    timeout=self.timeout,
                )
        except RunCommandError as e:
            raise SPDXError(f"Failed to update SPDX git repository") from e
        self.logger.info("SPDX git repository is up to date")

    # def _get_header_modified(self) -> datetime:
    #     try:
    #         res = requests.head(self.url, timeout=self.timeout)
    #     except RequestException as exc:
    #         raise RepocopError(f"Failed to reach Repocop at {self.url}") from exc

    #     return parsedate_to_datetime(res.headers["Last-Modified"])  # type: ignore

    # def _get_db_modified(self) -> datetime:
    #     try:
    #         res = self.conn.execute(self.sql.get_last_date)
    #         last_update = res[0][0]  # type: ignore
    #     except Exception as exc:
    #         if issubclass(exc.__class__, (DatabaseError,)):
    #             raise RepocopError("Failed get data from database") from exc

    #     return last_update.replace(tzinfo=tz.tzutc())  # type: ignore

    # def _get_repocop_status(self, repocop_updated: datetime) -> dict[str, Any]:
    #     try:
    #         res = requests.get(self.url, timeout=self.timeout)
    #         self.logger.debug(f"URL request elapsed {res.elapsed.total_seconds():.3f}")
    #     except RequestException as exc:
    #         raise RepocopError(f"Failed get information from {self.url}") from exc

    #     data = json.loads(bz2.decompress(res.content))
    #     self.logger.debug(f"Got {len(data)} records from Repocop report")
    #     for line in data:
    #         line["rc_test_date"] = repocop_updated

    #     return data

    # def _save_to_db(self, data: dict[str, Any]) -> None:
    #     try:
    #         res = self.conn.execute(self.sql.insert_repocop, data)
    #         self.logger.debug(
    #             f"Data loaded to database in {self.conn.last_query_elapsed:.3f} seconds"
    #         )
    #     except Exception as exc:
    #         if issubclass(exc.__class__, (DatabaseError,)):
    #             self.logger.error("Failed load data to database", exc_info=True)
    #             raise RepocopError("Failed load data to database") from exc

    def run(self) -> None:
        self._update_spdx_git()

    #     try:
    #         self.logger.info(f"Check Repocop for updates")
    #         repocop_date = self._get_header_modified()
    #         last_db_update_date = self._get_db_modified()

    #         if repocop_date > last_db_update_date:
    #             self.logger.info(f"Fetching Repocop data from {self.url}...")
    #             data = self._get_repocop_status(repocop_date)
    #             self.logger.info("Loading new Repocop data to database...")
    #             self._save_to_db(data)
    #             self.logger.info("Repocop data loaded to database")
    #         else:
    #             self.logger.info("Repocop data is up-to-date")
    #     except Exception as e:
    #         self.logger.error("Error occured while processing Repocop data")
    #         raise e
    #     finally:
    #         self.conn.disconnect()


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
            f"Error occurred while processing licenses from SPDX: {error}", exc_info=True
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
