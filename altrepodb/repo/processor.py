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
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

from altrepodb.base import DEFAULT_LOGGER, RepoProcessorConfig
from altrepodb.logger import LoggerProtocol
from altrepodb.database import DatabaseConfig

from .base import StringOrPath
from .parser import RepoParser
from .loader import RepoLoadHandler
from .exceptions import RepoParsingError, RepoProcessingError


@dataclass
class RepoProcessorConfig:
    name: str
    path: StringOrPath
    date: datetime
    dbconfig: DatabaseConfig
    logger: Optional[LoggerProtocol]
    tag: str = ""
    debug: bool = False
    force: bool = False
    verbose: bool = False
    workers: int = 8


class RepoProcessor:
    """Process and load repository to DB."""

    def __init__(self, config: RepoProcessorConfig) -> None:
        self.config = config

        if self.config.logger is not None:
            self.logger = self.config.logger
        else:
            self.logger = DEFAULT_LOGGER

        if self.config.debug:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

    def run(self) -> None:
        ts = time.time()
        self.logger.info("Start loading repository")
        try:
            rp = RepoParser(
                repo_name=self.config.name,
                repo_path=self.config.path,
                logger=self.logger
            )
            rlh = RepoLoadHandler(
                config=self.config,
                logger=self.logger
            )
            rlh.check_repo_in_db()
            self.logger.info(f"Start loading repository structure")
            rp.parse_repository()
            self.logger.info(
                f"Repository structure loaded, caches initialized in {(time.time() - ts):.3f} sec."
            )
            # load repository to DB
            rlh.upload(repo=rp.repo)
        except (RepoParsingError, RepoProcessingError) as e:
            raise e
        except Exception as e:
            self.logger.error(f"Failed to load repository to DB with: {e}")
            raise RepoProcessingError("Error occured while processin repository") from e
        else:
            self.logger.info(
                f"Repository loaded to DB in {(time.time() - ts):.3f} sec."
            )
        finally:
            self.logger.info("Stop loading repository")
