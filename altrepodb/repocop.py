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

import bz2
import json
import requests
from typing import Any
from logging import Logger
from dateutil import tz
from datetime import datetime
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from requests.exceptions import RequestException

from .database import DatabaseClient, DatabaseConfig, DatabaseError


class RepocopError(Exception):
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
class RepocopConfig:
    url: str
    logger: Logger
    dbconfig: DatabaseConfig
    timeout: int = 10


class Repocop:
    def __init__(self, config: RepocopConfig) -> None:
        self.sql = SQL()
        self.url = config.url
        self.conn = DatabaseClient(
            config=config.dbconfig,
            logger=config.logger,
        )
        self.logger = config.logger
        self.timeout = config.timeout

    def _get_header_modified(self) -> datetime:
        try:
            res = requests.head(self.url, timeout=self.timeout)
        except RequestException as exc:
            raise RepocopError(f"Failed to reach Repocop at {self.url}") from exc

        return parsedate_to_datetime(res.headers["Last-Modified"])  # type: ignore

    def _get_db_modified(self) -> datetime:
        try:
            res = self.conn.execute(self.sql.get_last_date)
            last_update = res[0][0]  # type: ignore
        except Exception as exc:
            if issubclass(exc.__class__, (DatabaseError,)):
                raise RepocopError("Failed get data from database") from exc

        return last_update.replace(tzinfo=tz.tzutc())  # type: ignore

    def _get_repocop_status(self, repocop_updated: datetime) -> dict[str, Any]:
        try:
            res = requests.get(self.url, timeout=self.timeout)
            self.logger.debug(f"URL request elapsed {res.elapsed.total_seconds():.3f}")
        except RequestException as exc:
            raise RepocopError(f"Failed get information from {self.url}") from exc

        data = json.loads(bz2.decompress(res.content))
        self.logger.debug(f"Got {len(data)} records from Repocop report")
        for line in data:
            line["rc_test_date"] = repocop_updated

        return data

    def _save_to_db(self, data: dict[str, Any]) -> None:
        try:
            _ = self.conn.execute(self.sql.insert_repocop, data)
            self.logger.debug(
                f"Data loaded to database in {self.conn.last_query_elapsed:.3f} seconds"
            )
        except Exception as exc:
            if issubclass(exc.__class__, (DatabaseError,)):
                self.logger.error("Failed load data to database", exc_info=True)
                raise RepocopError("Failed load data to database") from exc

    def run(self) -> None:
        try:
            self.logger.info("Check Repocop for updates")
            repocop_date = self._get_header_modified()
            last_db_update_date = self._get_db_modified()

            if repocop_date > last_db_update_date:
                self.logger.info(f"Fetching Repocop data from {self.url}...")
                data = self._get_repocop_status(repocop_date)
                self.logger.info("Loading new Repocop data to database...")
                self._save_to_db(data)
                self.logger.info("Repocop data loaded to database")
            else:
                self.logger.info("Repocop data is up-to-date")
        except Exception as e:
            self.logger.error("Error occured while processing Repocop data")
            raise e
        finally:
            self.conn.disconnect()
