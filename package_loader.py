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

import os
import sys
import time
import base64
import argparse
import configparser
from pathlib import Path
from dataclasses import dataclass

from altrpm import rpm, extractSpecAndHeadersFromRPM
from altrepodb.repo import PackageHandler
from altrepodb.database import DatabaseClient, DatabaseConfig
from altrepodb.utils import (
    cvt,
    snowflake_id_pkg,
    md5_from_file,
    sha256_from_file,
    blake2b_from_file,
    get_logging_options,
    check_package_in_cache,
)
from altrepodb.logger import get_logger, LoggerLevel, LoggerProtocol

NAME = "package"

os.environ["LANG"] = "C"


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="RPM package file")
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database password")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    parser.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="Force to load packages from task to database",
    )
    parser.add_argument(
        "-f",
        "--flush-buffers",
        action="store_true",
        help="Force to flush buffer tables after task loaded",
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
            get_logging_options(args, section_db)
    else:
        args.dbname = args.dbname or "default"
        args.host = args.host or "localhost"
        args.port = args.port or None
        args.user = args.user or "default"
        args.password = args.password or ""

    return args


@dataclass
class SQL:
    get_pkg_hshs_by_filename = """
SELECT pkg_hash FROM Packages_buffer WHERE pkg_filename = '{name}'
"""

    flush_tables_buffer = """
OPTIMIZE TABLE {buffer}
"""

    insert_spec_file = """
INSERT INTO Specfiles_insert (*) VALUES
"""


class PackageLoader:
    def __init__(self, pkg_file, conn, logger, args) -> None:
        self.sql = SQL()
        self.pkg = Path(pkg_file)
        self.conn = conn
        self.logger = logger
        self.force = args.force
        self.cache = self._init_cache()
        self.ph = PackageHandler(conn, logger)

    def _init_cache(self) -> set:
        result = self.conn.execute(
            self.sql.get_pkg_hshs_by_filename.format(name=self.pkg.name)
        )
        return {i[0] for i in result}

    def _get_header(self):  # return rpm header object
        return self.ph.get_header(str(self.pkg))

    def _get_file_size(self) -> int:
        try:
            file_size = self.pkg.stat().st_size
        except FileNotFoundError:
            return 0
        return file_size

    def _load_spec(self) -> None:
        self.logger.info(f"extracting spec file form {self.pkg.name}")
        st = time.time()
        spec_file, spec_contents, hdr = extractSpecAndHeadersFromRPM(self.pkg, raw=True)
        self.logger.debug(
            f"headers and spec file extracted in {(time.time() - st):.3f} seconds"
        )
        self.logger.info(f"Got {spec_file.name} spec file {spec_file.size} bytes long")  # type: ignore
        st = time.time()
        kw = {
            "pkg_hash": snowflake_id_pkg(hdr),
            "pkg_name": cvt(hdr[rpm.RPMTAG_NAME]),
            "pkg_epoch": cvt(hdr[rpm.RPMTAG_EPOCH], int),
            "pkg_version": cvt(hdr[rpm.RPMTAG_VERSION]),
            "pkg_release": cvt(hdr[rpm.RPMTAG_RELEASE]),
            "specfile_name": spec_file.name,  # type: ignore
            "specfile_date": spec_file.mtime,  # type: ignore
            "specfile_content_base64": base64.b64encode(spec_contents),  # type: ignore
        }
        self.conn.execute(self.sql.insert_spec_file, [kw,])
        self.logger.info(f"spec file loaded to DB in {(time.time() - st):.3f} seconds")

    def _insert_package(self, srpm_hash, is_srpm):
        st = time.time()
        kw = {}
        hdr = self._get_header()
        pkg_name = self.pkg.name
        # load only source packages for a now
        if not int(bool(hdr["RPMTAG_SOURCEPACKAGE"])):
            raise ValueError("Binary package files loading not supported yet")

        sha1 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_SHA1HEADER]))  # type: ignore
        hashes = {"sha1": sha1, "mmh": snowflake_id_pkg(hdr)}

        kw["pkg_hash"] = hashes["mmh"]
        kw["pkg_filename"] = pkg_name
        kw["pkg_filesize"] = self._get_file_size()
        if is_srpm:
            kw["pkg_sourcerpm"] = pkg_name
            kw["pkg_srcrpm_hash"] = hashes["mmh"]
        else:
            kw["pkg_srcrpm_hash"] = srpm_hash

        if self.force or not check_package_in_cache(self.cache, hashes["mmh"]):
            self.logger.debug(f"calculate MD5 for {pkg_name} file")
            hashes["md5"] = md5_from_file(self.pkg)

            self.logger.debug(f"calculate SHA256 for {pkg_name} file")
            hashes["sha256"] = sha256_from_file(self.pkg)

            self.logger.debug(f"calculate BLAKE2b for {pkg_name} file")
            hashes["blake2b"] = blake2b_from_file(self.pkg)

            self.ph.insert_package(hdr, self.pkg, **kw)
            self.ph.insert_pkg_hash_single(hashes)
            self.cache.add(hashes["mmh"])
            self.logger.info(
                f"package loaded in {(time.time() - st):.3f} seconds : {hashes['sha1'].hex()} : {kw['pkg_filename']}"
            )
        else:
            self.logger.info(
                f"package already loaded : {hashes['sha1'].hex()} : {kw['pkg_filename']}"
            )

        return hashes["mmh"]

    def load_package(self):
        self._insert_package(None, is_srpm=True)

    def flush(self):
        """Force flush bufeer tables using OPTIMIZE TABLE SQL requests."""
        buffer_tables = (
            "Files_buffer",
            "Depends_buffer",
            "Changelog_buffer",
            "Packages_buffer",
            "TaskIterations_buffer",
            "Tasks_buffer",
            "TaskStates_buffer",
            "Specfiles_buffer",
        )
        self.logger.info("Flushing buffer tables")
        for buffer in buffer_tables:
            self.conn.execute(self.sql.flush_tables_buffer.format(buffer=buffer))


def load(args, conn: DatabaseClient, logger: LoggerProtocol) -> None:
    pkgl = PackageLoader(args.file, conn, logger, args)
    pkgl.load_package()
    if args.flush_buffers:
        pkgl.flush()


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_logger(
        NAME,
        tag="load",
        log_to_file=getattr(args, "log_to_file", False),
        log_to_stderr=getattr(args, "log_to_console", True),
        log_to_syslog=getattr(args, "log_to_syslog", False),
    )
    if args.debug:
        logger.setLevel(LoggerLevel.DEBUG)
    conn = None
    try:
        logger.info("Start loading RPM package to database")
        logger.info("=" * 60)
        conn = DatabaseClient(
            config=DatabaseConfig(
                host=args.host,
                port=args.port,
                name=args.dbname,
                user=args.user,
                password=args.password,
            ),
            logger=logger,
        )
        if not Path(args.file).is_file():
            raise ValueError(f"{args.file} not a file")
        load(args, conn, logger)
    except Exception as error:
        logger.error(f"Error occurred during package loading: {error}", exc_info=True)
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()
    logger.info("=" * 60)
    logger.info("Stop loading RPM package to database")


if __name__ == "__main__":
    main()
