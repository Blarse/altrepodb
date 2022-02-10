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
import time
import logging
import datetime
import argparse
import configparser
from pathlib import Path
from typing import Any

from altrepodb.utils import (
    get_logger,
    valid_date,
    join_dicts_with_as_string,
    Timing,
    Display,
)
from altrepodb.database import DatabaseClient, DatabaseConfig
from altrepodb.base import LoggerProtocol
from altrepodb.misc import lut
from altrepodb.repo import (
    worker_pool,
    read_repo_structure,
    RepoLoadHandler,
    PackageSetHandler
)

NAME = "repo"

os.environ["LANG"] = "C"

def load(args: Any, logger: LoggerProtocol):
    conn = DatabaseClient(
            config=DatabaseConfig(
                host=args.host,
                port=args.port,
                name=args.dbname,
                user=args.user,
                password=args.password
            ),
            logger=logger
        )
    connections = [conn]
    display = None
    pkgset = set()
    ts = time.time()
    rlh = RepoLoadHandler(conn, logger)
    # set date if None
    if args.date is None:
        args.date = datetime.datetime.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    # check if {%name%}-{%date%} already in DB
    if rlh.check_repo_date_name_in_db(args.pkgset, args.date.date()):
        if not args.force:
            logger.error(
                f"Repository with name '{args.pkgset}' and "
                f"date '{args.date.date()}' already exists in database"
            )
            raise NameError("This package set is already loaded!")
    logger.info(f"Start loading repository structure")
    # read repo structures
    repo = read_repo_structure(args.pkgset, args.path, logger)
    repo["repo"]["kwargs"]["class"] = "repository"
    # init hash caches
    rlh.init_hash_temp_table(repo["src_hashes"])
    rlh.init_hash_temp_table(repo["pkg_hashes"])
    rlh.update_hases_from_db(repo["src_hashes"])
    rlh.update_hases_from_db(repo["pkg_hashes"])
    cache = rlh.init_cache(repo["src_hashes"], repo["pkg_hashes"])
    ts = time.time() - ts
    logger.info(f"Repository structure loaded, caches initialized in {ts:.3f} sec.")
    if args.verbose:
        display = Display(logger, ts)
    # store repository structure
    # level 0 : repository
    # rpository root loaded last as a 'transaction complete' sign
    repo_root = Path(repo["repo"]["path"])
    # level 1 : src
    # load source RPMs first
    # generate 'src.rpm' packages list
    pkg_count = 0
    pkg_count2 = 0
    ts = time.time()
    packages_list = []
    pkgset_cached = set()
    logger.info("Start checking SRC packages")
    # load source packages fom 'files/SRPMS'
    src_dir = Path.joinpath(repo_root, "files/SRPMS")
    if not src_dir.is_dir():
        raise RuntimeError("'files/SRPMS directory not found'")
    logger.info(f"Start checking SRC packages in {'/'.join(src_dir.parts[-2:])}")
    for pkg in repo["src_hashes"]:
        pkg_count += 1
        if repo["src_hashes"][pkg]["sha1"] is None:
            rpm_file = src_dir.joinpath(pkg)
            if not rpm_file.is_file():
                raise ValueError(f"File {rpm_file} not found")
            packages_list.append(str(rpm_file))
        else:
            pkgh = repo["src_hashes"][pkg]["mmh"]
            if not pkgh:
                raise ValueError(f"No hash found in cache for {pkg}")
            pkgset_cached.add(pkgh)
            pkg_count2 += 1
    logger.info(
        f"Checked {pkg_count} SRC packages. "
        f"{pkg_count2} packages in cache, "
        f"{len(packages_list)} packages for load. "
        f"Time elapsed {(time.time() - ts):.3f} sec."
    )
    # load 'src.rpm' packages
    worker_pool(
        logger,
        cache,
        repo["src_hashes"],
        repo["pkg_hashes"],
        packages_list,
        pkgset,
        display,
        True,
        args,
    )
    # build pkgset for PackageSet record
    pkgset.update(pkgset_cached)

    psh = PackageSetHandler(conn, logger)

    psh.insert_pkgset(repo["src"]["uuid"], pkgset)
    # store PackageSetName record for 'src'
    tmp_d = {"depth": "1", "type": "srpm", "size": str(len(pkgset))}
    tmp_d = join_dicts_with_as_string(tmp_d, repo["repo"]["kwargs"]["class"], "class")
    tmp_d = join_dicts_with_as_string(tmp_d, repo["src"]["path"], "SRPMS")
    tmp_d = join_dicts_with_as_string(tmp_d, repo["repo"]["name"], "repo")
    psh.insert_pkgset_name(
        name=repo["src"]["name"],
        uuid=repo["src"]["uuid"],
        puuid=repo["src"]["puuid"],
        ruuid=repo["repo"]["uuid"],
        depth=1,
        tag=args.tag,
        date=args.date,
        complete=1,
        kw_args=tmp_d,
    )

    # level 2: architectures
    for arch in repo["arch"]["archs"]:
        tmp_d = {"depth": "1", "type": "arch", "size": "0"}
        tmp_d = join_dicts_with_as_string(
            tmp_d, repo["repo"]["kwargs"]["class"], "class"
        )
        tmp_d = join_dicts_with_as_string(tmp_d, arch["path"], "path")
        tmp_d = join_dicts_with_as_string(tmp_d, repo["repo"]["name"], "repo")
        psh.insert_pkgset_name(
            name=arch["name"],
            uuid=arch["uuid"],
            puuid=arch["puuid"],
            ruuid=repo["repo"]["uuid"],
            depth=1,
            tag=args.tag,
            date=args.date,
            complete=1,
            kw_args=tmp_d,
        )
    # level 3: components
    for comp in repo["comp"]["comps"]:
        # load RPMs first
        pkgset = set()
        pkgset_cached = set()
        # generate 'rpm' packages list
        packages_list = []
        ts = time.time()
        pkg_count = 0
        logger.info(f"Start checking RPM packages in '{comp['path']}'")
        rpm_dir = Path.joinpath(repo_root, comp["path"])
        # proceed binary packages using repo["bin_pkgs"] dictionary
        arch_ = comp["path"].split("/")[0]
        comp_ = comp["path"].split(".")[-1]
        for pkg in repo["bin_pkgs"][(arch_, comp_)]:
            rpm_file = rpm_dir.joinpath(pkg)
            pkg_count += 1
            if repo["pkg_hashes"][pkg]["sha1"] is None:
                if not rpm_file.is_file():
                    raise ValueError(f"File {pkg} not found in {comp['path']}")
                packages_list.append(str(rpm_file))
            else:
                pkgh = repo["pkg_hashes"][rpm_file.name]["mmh"]
                if not pkgh:
                    raise ValueError(f"No hash found in cache for {pkg}")
                pkgset_cached.add(pkgh)
        logger.info(
            f"Checked {pkg_count} RPM packages. "
            f"{len(packages_list)} packages for load. "
            f"Time elapsed {(time.time() - ts):.3f} sec."
        )
        # load '.rpm' packages
        worker_pool(
            logger,
            cache,
            repo["src_hashes"],
            repo["pkg_hashes"],
            packages_list,
            pkgset,
            display,
            False,
            args,
        )
        # build pkgset for PackageSet record
        pkgset.update(pkgset_cached)

        psh.insert_pkgset(comp["uuid"], pkgset)
        # store PackageSetName record
        tmp_d = {"depth": "2", "type": "comp", "size": str(len(pkgset))}
        tmp_d = join_dicts_with_as_string(
            tmp_d, repo["repo"]["kwargs"]["class"], "class"
        )
        tmp_d = join_dicts_with_as_string(tmp_d, comp["path"], "path")
        tmp_d = join_dicts_with_as_string(tmp_d, repo["repo"]["name"], "repo")
        psh.insert_pkgset_name(
            name=comp["name"],
            uuid=comp["uuid"],
            puuid=comp["puuid"],
            ruuid=repo["repo"]["uuid"],
            depth=2,
            tag=args.tag,
            date=args.date,
            complete=1,
            kw_args=tmp_d,
        )
    # level 0 : repository
    tmp_d = {
        "depth": "0",
        "type": "repo",
        "size": str(len(repo["src_hashes"]) + len(repo["pkg_hashes"])),
    }
    tmp_d = join_dicts_with_as_string(tmp_d, repo["repo"]["kwargs"], None)
    tmp_d = join_dicts_with_as_string(
        tmp_d, repo["arch"]["kwargs"]["all_archs"], "archs"
    )
    tmp_d = join_dicts_with_as_string(
        tmp_d, repo["comp"]["kwargs"]["all_comps"], "comps"
    )
    psh.insert_pkgset_name(
        name=repo["repo"]["name"],
        uuid=repo["repo"]["uuid"],
        puuid=repo["repo"]["puuid"],
        ruuid=repo["repo"]["uuid"],
        depth=0,
        tag=args.tag,
        date=args.date,
        complete=1,
        kw_args=tmp_d,
    )

    for c in connections:
        if c is not None:
            c.disconnect()

    if display is not None:
        display.conclusion()


def get_args():
    parser = argparse.ArgumentParser(
        prog="repo_loader",
        description="Load repository structure from file system to database",
    )
    parser.add_argument("pkgset", type=str, help="Repository name")
    parser.add_argument("path", type=str, help="Path to packages")
    parser.add_argument("-t", "--tag", type=str, help="Assignment tag", default="")
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file")
    parser.add_argument("-d", "--dbname", type=str, help="Database name")
    parser.add_argument("-s", "--host", type=str, help="Database host")
    parser.add_argument("-p", "--port", type=str, help="Database port")
    parser.add_argument("-u", "--user", type=str, help="Database login")
    parser.add_argument("-P", "--password", type=str, help="Database password")
    parser.add_argument("-w", "--workers", type=int, help="Workers count (default: 10)")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )
    parser.add_argument(
        "-T", "--timing", action="store_true", help="Enable timing for functions"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose mode"
    )
    parser.add_argument(
        "-A",
        "--date",
        type=valid_date,
        help="Set repository datetime release. Format YYYY-MM-DD",
    )
    parser.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="Force to load repository with same name and date as existing one in database",
    )
    return parser.parse_args()


def get_config(args):
    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)
        # default
        args.workers = args.workers or cfg["DEFAULT"].getint("workers", 10)
        # database
        if cfg.has_section("DATABASE"):
            section_db = cfg["DATABASE"]
            args.dbname = args.dbname or section_db.get("dbname", "default")
            args.host = args.host or section_db.get("host", "localhost")
            args.port = args.port or section_db.get("port", None)
            args.user = args.user or section_db.get("user", "default")
            args.password = args.password or section_db.get("password", "")
    else:
        args.workers = args.workers or 10
        args.dbname = args.dbname or "default"
        args.host = args.host or "localhost"
        args.port = args.port or None
        args.user = args.user or "default"
        args.password = args.password or ""
    return args


def main():
    args = get_args()
    args = get_config(args)
    # avoid repository name accidentally contains capital letters
    args.pkgset = args.pkgset.lower()
    logger = get_logger(NAME, args.pkgset, args.date)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.timing:
        Timing.timing = True
    logger.info(f"run with args: {args}")
    logger.info("start loading packages")
    try:
        load(args, logger)
    except Exception as error:
        logger.error(str(error), exc_info=True)
    finally:
        logger.info("stop loading packages")


if __name__ == "__main__":
    main()
