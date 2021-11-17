import os
import sys
import time
import base64
import logging
import argparse
import configparser
from pathlib import Path
from dataclasses import dataclass
from clickhouse_driver import Client

import altrpm
import extract
from utils import (
    cvt,
    get_logger,
    snowflake_id,
    md5_from_file,
    sha256_from_file,
    blake2b_from_file,
)


NAME = "package"

os.environ["LANG"] = "C"


def get_client(args) -> Client:
    """Get Clickhouse client instance."""
    client = Client(
        args.host,
        port=args.port,
        database=args.dbname,
        user=args.user,
        password=args.password,
    )
    client.connection.connect()
    return client


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

    def _init_cache(self) -> set:
        result = self.conn.execute(
            self.sql.get_pkg_hshs_by_filename.format(name=self.pkg.name)
        )
        return {i[0] for i in result}

    def _get_header(self):  # return rpm header object
        self.logger.debug(f"reading header for {self.pkg}")
        return extract.get_header(self.pkg, self.logger)

    def _get_file_size(self) -> int:
        try:
            file_size = self.pkg.stat().st_size
        except FileNotFoundError:
            return 0
        return file_size

    def _load_spec(self) -> None:
        self.logger.info(f"extracting spec file form {self.pkg.name}")
        st = time.time()
        spec_file, spec_contents, hdr = altrpm.extractSpecAndHeadersFromRPM(
            self.pkg, raw=True
        )
        self.logger.debug(
            f"headers and spec file extracted in {(time.time() - st):.3f} seconds"
        )
        self.logger.info(f"Got {spec_file.name} spec file {spec_file.size} bytes long")
        st = time.time()
        kw = {
            "pkg_hash": snowflake_id(hdr),
            "pkg_name": cvt(hdr["RPMTAG_NAME"]),
            "pkg_epoch": cvt(hdr["RPMTAG_EPOCH"], int),
            "pkg_version": cvt(hdr["RPMTAG_VERSION"]),
            "pkg_release": cvt(hdr["RPMTAG_RELEASE"]),
            "specfile_name": spec_file.name,
            "specfile_date": spec_file.mtime,
            "specfile_content_base64": base64.b64encode(spec_contents),
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

        sha1 = bytes.fromhex(cvt(hdr["RPMSIGTAG_SHA1"]))
        hashes = {"sha1": sha1, "mmh": snowflake_id(hdr)}

        self.logger.debug(f"calculate MD5 for {pkg_name} file")
        hashes["md5"] = md5_from_file(self.pkg, as_bytes=True)

        self.logger.debug(f"calculate SHA256 for {pkg_name} file")
        hashes["sha256"] = sha256_from_file(self.pkg, as_bytes=True)

        self.logger.debug(f"calculate BLAKE2b for {pkg_name} file")
        hashes["blake2b"] = blake2b_from_file(self.pkg, as_bytes=True)

        kw["pkg_hash"] = hashes["mmh"]
        kw["pkg_filename"] = pkg_name
        kw["pkg_filesize"] = self._get_file_size()
        if is_srpm:
            kw["pkg_sourcerpm"] = pkg_name
            kw["pkg_srcrpm_hash"] = hashes["mmh"]
        else:
            kw["pkg_srcrpm_hash"] = srpm_hash

        if self.force or not extract.check_package_in_cache(self.cache, hashes["mmh"]):
            extract.insert_package(self.conn, self.logger, hdr, self.pkg, **kw)
            extract.insert_pkg_hash_single(self.conn, hashes)
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


def load(args, conn: Client, logger: logging.Logger) -> None:
    pkgl = PackageLoader(args.file, conn, logger, args)
    pkgl.load_package()
    if args.flush_buffers:
        pkgl.flush()


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_logger(NAME, tag="load")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    conn = None
    try:
        logger.info("Start loading RPM package to database")
        logger.info("=" * 60)
        conn = get_client(args)
        if not Path(args.file).is_file():
            raise ValueError(f"{args.file} not a file")
        load(args, conn, logger)
    except Exception as error:
        logger.exception("Error occurred during package loading")
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()
    logger.info("=" * 60)
    logger.info("Stop loading RPM package to database")


if __name__ == "__main__":
    main()
