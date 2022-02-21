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

import os
import sys
import time
import argparse
import configparser
from pathlib import Path

from altrepodb.base import ImageProcessorConfig, LoggerProtocol, ImageMeta
from altrepodb.image import ImageProcessor
from altrepodb.database import DatabaseConfig
from altrepodb.utils import valid_url, valid_date, valid_version
from altrepodb.logger import get_config_logger

NAME = "image"
ARCHS = ("i586", "x86_64", "aarch64", "ppc64le")
VARIANTS = ("install", "live", "rescue", "recovery")
RELEASES = ("alpha", "beta", "rc", "release")
EDITIONS = (
    "alt-server",
    "alt-server-v",
    "alt-education",
    "alt-workstation",
    "alt-kworkstation",
    "slinux",
    "cloud",
)
FLAVORS = ("",)
PLATFORMS = (
    "",
    "rpi4",
    "tegra",
    "baikalm",
    "tavolga",
    "bfk3",
    "mcom02",
    "hifive",
    "qemu",
)
IMAGE_TYPES = ("tar", "img", "qcow")

os.environ["LANG"] = "C"


def check_edition(edition: str) -> str:
    """Check filesystem image edition is starting with valid prefixes."""

    matched = False
    for ed in EDITIONS:
        if edition.strip().startswith(ed):
            matched = True
            break
    if not matched:
        raise argparse.ArgumentTypeError(
            "ISO image edition doesn't match with any valid prefixes"
        )

    return edition


def get_args():
    parser = argparse.ArgumentParser(
        prog="image_loader",
        description="Load filesystem image structure to database",
    )
    parser.add_argument("path", type=str, help="Path to filesystem image file")
    parser.add_argument(
        "--edition",
        required=True,
        type=str,
        choices=EDITIONS,
        help="Filesystem image edition",
    )
    parser.add_argument(
        "--version",
        required=True,
        type=valid_version,
        help="Filesystem image version (e.g. 9.2, 8.1.3, 20211205)",
    )
    parser.add_argument(
        "--release",
        required=True,
        type=str,
        choices=RELEASES,
        help="Filesystem image release type",
    )
    parser.add_argument(
        "--platform",
        required=True,
        type=str,
        choices=PLATFORMS,
        default="",
        help="Filesystem image platform",
    )
    parser.add_argument(
        "--variant",
        required=True,
        type=str,
        choices=VARIANTS,
        help="Filesystem image variant",
    )
    parser.add_argument(
        "--type",
        required=True,
        type=str,
        choices=IMAGE_TYPES,
        help="Filesystem image type",
    )
    parser.add_argument(
        "--flavor",
        required=True,
        type=str,
        default="",
        help="Filesystem image flavor",
    )
    parser.add_argument(
        "--arch", required=True, type=str, choices=ARCHS, help="Filesystem image arch"
    )
    parser.add_argument(
        "--branch", required=True, type=str, help="Filesystem image base branch name"
    )
    parser.add_argument(
        "--date", required=True, type=valid_date, help="Filesystem image date"
    )
    parser.add_argument(
        "--url", required=True, type=valid_url, help="Filesystem image download URL"
    )
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
        help="Force to load packages to database",
    )
    parser.add_argument(
        "-t",
        "--dry-run",
        action="store_true",
        help="Do not load data to database",
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


def load(args, dbconfig: DatabaseConfig, logger: LoggerProtocol) -> None:
    config = ImageProcessorConfig(
        path=args.path,
        logger=logger,
        dbconfig=dbconfig,
        debug=args.debug,
        force=args.force,
        dryrun=args.dry_run,
    )
    mj_, mn_, su_ = args.version
    meta = ImageMeta(
        file=Path(args.path).name,
        arch=args.arch,
        date=args.date,
        branch=args.branch,
        flavor=args.flavor,
        edition=args.edition,
        variant=args.variant,
        platform=args.platform,
        image_type=args.type,
        release=args.release,
        version_major=mj_,
        version_minor=mn_,
        version_sub=su_,
        url=args.url,
    )
    iso = ImageProcessor(config=config, image_meta=meta)
    iso.run()


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"
    args = get_args()
    logger = get_config_logger(
        NAME,
        tag="load",
        config=args.config,
    )
    logger.info(f"Run with args: {args}")
    conn = None
    st = time.time()
    try:
        logger.info("Start loading filesystem image to database")
        logger.info("=" * 60)
        config = DatabaseConfig(
            host=args.host,
            port=args.port,
            name=args.dbname,
            user=args.user,
            password=args.password,
        )
        if not Path(args.path).is_file():
            raise ValueError(f"{args.path} is not a file")
        load(args, config, logger)
        logger.info(
            f"Filesystem image {Path(args.path).name} loaded in {(time.time() - st):.3f} seconds"
        )
    except Exception as error:
        logger.error(
            f"Error occurred during filesystem image loading: {error}", exc_info=True
        )
        sys.exit(1)
    finally:
        if conn is not None:
            conn.disconnect()
    logger.info("=" * 60)
    logger.info("Stop loading filesystem image to database")


if __name__ == "__main__":
    main()
