# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021 BaseALT Ltd
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

from typing import Any
from clickhouse_driver import Client, errors

from .base import DatabaseConfig, DEFAULT_LOGGER
from .logger import _LoggerOptional

class DatabaseError(Exception):
    pass

class DatabaseConnectionError(DatabaseError):
    """Raised when failed to connect to database."""

    def __init__(self, message: str, exc: Exception):
        self.message = message
        self.exc = exc
        super().__init__(f"Message: {self.message}. Exception: {self.exc}")


class DatabaseExceptionRaisedError(DatabaseError):
    """Raised when CLickhouse server returned an exception."""

    def __init__(self, message: str, exc: Exception):
        self.message = message
        self.exc = exc
        super().__init__(f"Message: {self.message}. Exception: {self.exc}")


class DatabaseClient:
    """Clickhouse database client protocol."""

    def __init__(self, config: DatabaseConfig, logger: _LoggerOptional) -> None:
        self.config = config
        self.connected = False
        if logger is not None:
            self.logger = logger
        else:
            self.logger = DEFAULT_LOGGER(name="database")
        self.conn = self._get_connection()

    def _get_connection(self):
        client = Client(
            self.config.name,
            port=self.config.port,
            database=self.config.name,
            user=self.config.user,
            password=self.config.password,
        )
        self.logger.debug(
            f"Connecting to database {self.config.name} "
            f"at {self.config.host}:{self.config.port}"
        )
        try:
            client.connection.connect()
            self.connected = True
        except errors.NetworkError as error:
            self.logger.error(f"Failed connect to Database")
            raise DatabaseConnectionError(f"Failed connect to Database", error)
        except errors.Error as error:
            self.logger.error(f"An exception ocured while connecting to database: {error}")
            raise DatabaseExceptionRaisedError(f"Failed connect to Database", error)
        except Exception as error:
            self.logger.error(f"An exception ocured while connecting to database: {error}")
            raise error
        return client

    def execute(self, *args, **kwargs) -> Any:
        if not self.connected:
            self._get_connection
        try:
            res = self.conn.execute(*args, **kwargs)
        except errors.Error as error:
            self.logger.error(f"Database exception ocured processing SQL request: {error}")
            raise DatabaseExceptionRaisedError(
                f"Database exception ocured processing SQL request", error
            )
        except Exception as error:
            self.logger.error(f"An exception ocured while connecting to database: {error}")
            raise error
        self.logger.debug(
            f"SQL request elapsed {self.conn.last_query.elapsed:.3f} seconds"  # type: ignore
        )
        return res

    def disconnect(self) -> None:
        self.logger.debug(f"Closing connection to database")
        if self.connected:
            self.conn.disconnect()
            self.connected = False
