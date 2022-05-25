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

import requests
from logging import Logger
from dateutil import tz
from datetime import datetime
from dataclasses import dataclass
from requests.exceptions import RequestException
from email.utils import parsedate_to_datetime

from .database import DatabaseClient, DatabaseConfig, DatabaseError


class WatchError(Exception):
    pass


@dataclass(frozen=True)
class SQL:
    get_last_date = """
SELECT max(date_update) FROM PackagesWatch
"""

    insert_watch = """
INSERT INTO PackagesWatch (*) VALUES
"""


@dataclass
class WatchConfig:
    url: str
    logger: Logger
    dbconfig: DatabaseConfig
    timeout: int = 10


class Watch:
    def __init__(self, config: WatchConfig) -> None:
        self.sql = SQL()
        self.url = config.url
        self.conn = self.conn = DatabaseClient(
            config=config.dbconfig,
            logger=config.logger,
        )
        self.logger = config.logger
        self.timeout = config.timeout

    def _get_watch(self) -> tuple[requests.Response, datetime]:
        try:
            res = requests.get(self.url, timeout=self.timeout)
        except RequestException:
            raise WatchError(f"Failed get information from {self.url}")

        return res, parsedate_to_datetime(res.headers["Last-Modified"])  # type: ignore

    def _get_db_modified(self) -> datetime:
        try:
            res_db = self.conn.execute(self.sql.get_last_date)
            last_update = res_db[0][0]  # type: ignore
        except Exception as exc:
            if issubclass(exc.__class__, (DatabaseError,)):
                raise WatchError("Failed get data from database") from exc

        return last_update.replace(tzinfo=tz.tzutc())  # type: ignore

    def _save_to_db(self, data: list[str], watch_modified: datetime) -> None:
        result = []
        for line in data:
            line = line.split("\t")
            if line != [""]:
                el_dict = {
                    "acl": line[0],
                    "pkg_name": line[1],
                    "old_version": line[2],
                    "new_version": line[3],
                    "url": line[4],
                    "date_update": watch_modified,
                }
                result.append(el_dict)

        try:
            self.conn.execute(self.sql.insert_watch, result)
        except Exception as exc:
            if issubclass(exc.__class__, (DatabaseError,)):
                raise WatchError("Failed load data to database") from exc

    def run(self) -> None:
        try:
            self.logger.info("Check Watch for updates")
            res_watch, watch_last_modified = self._get_watch()
            last_db_update_date = self._get_db_modified()

            if watch_last_modified > last_db_update_date:
                self.logger.info("Loading new watch data to database...")
                data = res_watch.text.split("\n")
                self._save_to_db(data, watch_last_modified)
                self.logger.info("Watch data loaded to database")
            else:
                self.logger.info("Watch data up-to-date")
        except Exception as e:
            self.logger.error("Error occured while processing Watch data")
            raise e
        finally:
            self.conn.disconnect()
