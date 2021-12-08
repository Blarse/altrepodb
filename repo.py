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
import time
import base64
import logging
import datetime
import argparse
import itertools
import threading
import configparser
import multiprocessing
import clickhouse_driver as chd
from uuid import uuid4
from pathlib import Path
from rpm import TransactionSet
from collections import defaultdict
from typing import Any, Iterable, Union

from altrpm import rpm, extractSpecFromRPM, readHeaderListFromXZFile
import altrepo_db.mapper as mapper
from altrepo_db.utils import (
    cvt,
    unxz,
    get_logger,
    get_client,
    valid_date,
    md5_from_file,
    sha256_from_file,
    blake2b_from_file,
    check_package_in_cache,
    join_dicts_with_as_string,
    Timing,
    Display,
)
from altrepo_db.base import LockedIterator, NotImplementedError, PackageLoadError


NAME = "extract"
ARCHS = (
    "src",
    "aarch64",
    "armh",
    "i586",
    "ppc64le",
    "x86_64",
    "x86_64-i586",
    "noarch",
    "mipsel",
    "riscv64",
    "e2k",
    "e2kv4",
    "e2kv5",
)

os.environ["LANG"] = "C"


class PackageHandler:
    """Handle package header parsing and insertion to DB."""

    def __init__(self, conn: chd.Client, logger: logging.Logger):
        self.conn = conn
        self.logger = logger

    @staticmethod
    def get_header(rpmfile: str) -> Any:
        # return readHeaderFromRPM(rpmfile)
        ts = TransactionSet()
        return ts.hdrFromFdno(rpmfile)

    @Timing.timeit(NAME)
    def insert_package(self, hdr, pkg_file, **kwargs):
        """Insert information about package into database.

        Also:
        insert packager, files, requires, provides, confilcts, obsolets
        """
        map_package = mapper.get_package_map(hdr)
        map_package.update(**kwargs)
        # formatting changelog
        chlog = map_package["pkg_changelog"]
        del map_package["pkg_changelog"]
        map_package["pkg_changelog.date"] = []
        map_package["pkg_changelog.name"] = []
        map_package["pkg_changelog.evr"] = []
        map_package["pkg_changelog.hash"] = []

        for el in chlog:
            map_package["pkg_changelog.date"].append(el[0])
            map_package["pkg_changelog.name"].append(el[1])
            map_package["pkg_changelog.evr"].append(el[2])
            map_package["pkg_changelog.hash"].append(el[4])

        payload = [
            {"chlog_hash": r[0], "chlog_text": r[1]}
            for r in {(el[4], el[3]) for el in chlog}
        ]

        self.conn.execute("""INSERT INTO Changelog_buffer (*) VALUES""", payload)

        sql_insert = "INSERT INTO Packages_buffer ({0}) VALUES".format(
            ", ".join(map_package.keys())
        )

        pkghash = map_package["pkg_hash"]

        self.insert_file(pkghash, hdr)

        map_require = mapper.get_require_map(hdr)
        self.insert_list(map_require, pkghash, "require")

        map_conflict = mapper.get_conflict_map(hdr)
        self.insert_list(map_conflict, pkghash, "conflict")

        map_obsolete = mapper.get_obsolete_map(hdr)
        self.insert_list(map_obsolete, pkghash, "obsolete")

        map_provide = mapper.get_provide_map(hdr)
        self.insert_list(map_provide, pkghash, "provide")

        self.conn.execute(sql_insert, [map_package])

        if map_package["pkg_sourcepackage"] == 1:
            self.insert_specfile(pkg_file, map_package)

        return pkghash

    @Timing.timeit(NAME)
    def insert_specfile(self, pkg_file, pkg_map):
        self.logger.debug(f"extracting spec file form {pkg_map['pkg_filename']}")
        st = time.time()
        spec_file, spec_contents = extractSpecFromRPM(pkg_file, raw=True)
        self.logger.debug(
            f"headers and spec file extracted in {(time.time() - st):.3f} seconds"
        )
        self.logger.debug(f"Got {spec_file.name} spec file {spec_file.size} bytes long")
        st = time.time()
        kw = {
            "pkg_hash": pkg_map["pkg_hash"],
            "pkg_name": pkg_map["pkg_name"],
            "pkg_epoch": pkg_map["pkg_epoch"],
            "pkg_version": pkg_map["pkg_version"],
            "pkg_release": pkg_map["pkg_release"],
            "specfile_name": spec_file.name,
            "specfile_date": spec_file.mtime,
            "specfile_content_base64": base64.b64encode(spec_contents),
        }
        self.conn.execute(
            "INSERT INTO Specfiles_insert (*) VALUES",
            [
                kw,
            ],
        )
        self.logger.debug(f"spec file loaded to DB in {(time.time() - st):.3f} seconds")

    @Timing.timeit(NAME)
    def insert_file(self, pkghash, hdr):
        map_file = mapper.get_file_map(hdr)
        map_file["pkg_hash"] = itertools.cycle([pkghash])
        data = mapper.unpack_map(map_file)
        self.conn.execute(
            "INSERT INTO Files_insert ({0}) VALUES".format(", ".join(map_file.keys())),
            data,
        )
        self.logger.debug("insert file for pkghash: {0}".format(pkghash))

    @Timing.timeit("extract")
    def insert_list(self, tagmap, pkghash, dptype):
        """Insert list as batch."""
        tagmap["pkg_hash"] = itertools.cycle([pkghash])
        tagmap["dp_type"] = itertools.cycle([dptype])
        data = mapper.unpack_map(tagmap)
        self.conn.execute(
            "INSERT INTO Depends_buffer ({0}) VALUES".format(", ".join(tagmap.keys())),
            data,
        )
        self.logger.debug(
            "insert list into: {0} for pkghash: {1}".format(dptype, pkghash)
        )

    @Timing.timeit(NAME)
    def insert_pkg_hashes(self, pkg_hashes):
        """Inserts multiple packages hashes to DB

        Args:
            conn (connection): ClickHouse driver connection object
            pkg_hashes (dict[dict]): dictionary of packages hashes
        """
        payload = []
        for v in pkg_hashes.values():
            payload.append(
                {
                    "pkgh_mmh": v["mmh"],
                    "pkgh_md5": v["md5"],
                    "pkgh_sha1": v["sha1"],
                    "pkgh_sha256": v["sha256"],
                    "pkgh_blake2b": v["blake2b"],
                }
            )
        settings = {"strings_as_bytes": True}
        self.conn.execute(
            "INSERT INTO PackageHash_buffer (*) VALUES", payload, settings=settings
        )

    @Timing.timeit(NAME)
    def insert_pkg_hash_single(self, pkg_hash):
        """Insert single package hashes to DB

        Args:
            conn (connection): ClickHouse driver connection object
            pkg_hash (dict): dictionary of single package hashes
        """
        settings = {"strings_as_bytes": True}
        self.conn.execute(
            "INSERT INTO PackageHash_buffer (*) VALUES",
            [
                {
                    "pkgh_mmh": pkg_hash["mmh"],
                    "pkgh_md5": pkg_hash["md5"],
                    "pkgh_sha1": pkg_hash["sha1"],
                    "pkgh_sha256": pkg_hash["sha256"],
                    "pkgh_blake2b": pkg_hash["blake2b"],
                }
            ],
            settings=settings,
        )


class PackageSetHandler:
    """Handle package set records insertion to DB."""

    def __init__(self, conn: chd.Client, logger: logging.Logger):
        self.conn = conn
        self.logger = logger

    @Timing.timeit(NAME)
    def insert_pkgset_name(
        self, name, uuid, puuid, ruuid, depth, tag, date, complete, kv_args
    ):
        if date is None:
            date = datetime.datetime.now().replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        sql = "INSERT INTO PackageSetName (*) VALUES"
        data = {
            "pkgset_uuid": uuid,
            "pkgset_puuid": puuid,
            "pkgset_ruuid": ruuid,
            "pkgset_depth": depth,
            "pkgset_nodename": name,
            "pkgset_date": date,
            "pkgset_tag": tag,
            "pkgset_complete": complete,
            "pkgset_kv.k": [k for k, v in kv_args.items() if v is not None],
            "pkgset_kv.v": [v for k, v in kv_args.items() if v is not None],
        }
        self.conn.execute(sql, [data])
        self.logger.debug("insert package set name uuid: {0}".format(uuid))

    @Timing.timeit(NAME)
    def insert_pkgset(self, uuid, pkghash):
        self.conn.execute(
            "INSERT INTO PackageSet_buffer (pkgset_uuid, pkg_hash) VALUES",
            [dict(pkgset_uuid=uuid, pkg_hash=p) for p in pkghash],
        )
        self.logger.debug(
            "insert package set uuid: {0}, pkg_hash: {1}".format(uuid, len(pkghash))
        )


class Worker(threading.Thread):
    """Package loader worker."""

    def __init__(
        self,
        connection: chd.Client,
        logger: logging.Logger,
        lock: threading.Lock,
        pkg_cache: set,
        src_repo_cache: dict,
        pkg_repo_cache: dict,
        packages: Iterable,
        pkgset: set,
        display: Union[Display, None],
        is_src: bool = False,
        *args,
        **kwargs,
    ):
        self.connection = connection
        self.logger = logger
        self.packages = packages
        self.pkgset = pkgset
        self.display = display
        self.src_repo_cache = src_repo_cache
        self.pkg_repo_cache = pkg_repo_cache
        self.cache = pkg_cache
        self.is_src = is_src
        self.exc = None
        self.exc_args = None
        self.lock = lock
        self.ph = PackageHandler(connection, logger)
        super().__init__(*args, **kwargs)

    def run(self):
        self.logger.debug("thread start")
        for package in self.packages:
            try:
                pkg_filename = Path(package).name
                header = self.ph.get_header(package)
                map_package = mapper.get_partial_pkg_map(
                    header,
                    (
                        "pkg_sourcepackage",
                        "pkg_sourcerpm",
                        "pkg_hash",
                        "pkg_arch",
                        "pkg_cs",
                    ),
                )
                kw = {
                    "pkg_filename": pkg_filename,
                    "pkg_filesize": Path(package).stat().st_size,
                }
                # add thread safety lock here
                with self.lock:
                    if self.is_src:
                        #  store pkg mmh and sha1
                        self.src_repo_cache[pkg_filename]["mmh"] = map_package["pkg_hash"]
                        self.src_repo_cache[pkg_filename]["sha1"] = map_package["pkg_cs"]
                        # set source rpm name and hash to self
                        kw["pkg_sourcerpm"] = pkg_filename
                        kw["pkg_srcrpm_hash"] = map_package["pkg_hash"]
                        # check if BLAKE2b hash found and if not, calculate it from file
                        if self.src_repo_cache[pkg_filename]["blake2b"] in (b"", None):
                            self.logger.debug(
                                f"calculate BLAKE2b for {pkg_filename} file"
                            )
                            self.src_repo_cache[pkg_filename][
                                "blake2b"
                            ] = blake2b_from_file(package, as_bytes=True)
                    else:
                        #  store pkg mmh and sha1
                        self.pkg_repo_cache[pkg_filename]["mmh"] = map_package["pkg_hash"]
                        self.pkg_repo_cache[pkg_filename]["sha1"] = map_package["pkg_cs"]
                        # set source rpm name and hash
                        kw["pkg_srcrpm_hash"] = self.src_repo_cache[map_package["pkg_sourcerpm"]]["mmh"]
                        # check if BLAKE2b hash found and if not, calculate it from file
                        if self.pkg_repo_cache[pkg_filename]["blake2b"] in (b"", None):
                            self.logger.debug(
                                f"calculate BLAKE2b for {pkg_filename} file"
                            )
                            self.pkg_repo_cache[pkg_filename]["blake2b"] = blake2b_from_file(
                                package, as_bytes=True
                            )

                # check if 'pkg_srcrpm_hash' is None - it's Ok for 'x86_64-i586'
                if (
                    map_package["pkg_arch"] == "x86_64-i586"
                    and kw["pkg_srcrpm_hash"] is None
                ):
                    kw["pkg_srcrpm_hash"] = 0

                self.logger.debug("process: {0}".format(package))
                pkghash = check_package_in_cache(self.cache, map_package["pkg_hash"])

                if pkghash is None:
                    pkghash = self.ph.insert_package(header, package, **kw)
                    self.cache.add(pkghash)
                    # insert package hashes to PackageHash_buffer
                    if self.is_src:
                        self.ph.insert_pkg_hash_single(
                            self.src_repo_cache[pkg_filename]
                        )
                    else:
                        self.ph.insert_pkg_hash_single(
                            self.pkg_repo_cache[pkg_filename]
                        )
                if pkghash is None:
                    raise PackageLoadError(
                        f"No hash for {package} from 'insert_package()'"
                    )
                self.pkgset.add(pkghash)
            except Exception as error:
                self.logger.error(error, exc_info=True)
                self.exc = error
                self.exc_args = {"package": package, "hash": pkghash}  # type: ignore
                break
            else:
                if self.display is not None:
                    self.display.inc()
        self.logger.debug("thread stop")

    def join(self):
        super().join()
        if self.exc:
            msg = (
                f"Exception occured in {self.name} for package "
                f"{self.exc_args['package']} with {self.exc_args['hash']}"  # type: ignore
            )
            raise PackageLoadError(msg) from self.exc


def worker_pool(
    logger: logging.Logger,
    pkg_cache: set,
    src_repo_cache: dict,
    pkg_repo_cache: dict,
    packages_list: Iterable,
    pkgset: set,
    display: Union[Display, None],
    is_src: bool,
    args: Any,
):
    lock = threading.Lock()
    workers: list[Worker] = []
    connections: list[chd.Client] = []

    packages = LockedIterator((pkg for pkg in packages_list))

    for i in range(args.workers):
        conn = get_client(args)
        connections.append(conn)
        worker = Worker(
            conn,
            logger,
            lock,
            pkg_cache,
            src_repo_cache,
            pkg_repo_cache,
            packages,
            pkgset,
            display,
            is_src,
        )
        worker.start()
        workers.append(worker)

    for w in workers:
        try:
            w.join()
        except PackageLoadError as e:
            logger.error(f"Error: {e.message}")
            raise e

    for c in connections:
        if c is not None:
            c.disconnect()


class RepoLoadHandler:
    """Handle repository structure processing and loading to DB."""

    def __init__(self, conn: chd.Client, logger: logging.Logger):
        self.conn = conn
        self.logger = logger

    @staticmethod
    def init_cache(src_hashes: dict, bin_hashes: dict) -> set:
        cache = set()
        for v in src_hashes.values():
            if v["mmh"] != 0:
                cache.add(v["mmh"])
        for v in bin_hashes.values():
            if v["mmh"] != 0:
                cache.add(v["mmh"])

        return cache

    @Timing.timeit(NAME)
    def init_hash_temp_table(self, hashes: dict) -> None:
        payload = []
        result = self.conn.execute(
"""
CREATE TEMPORARY TABLE IF NOT EXISTS PkgHashTmp
(
    name    String,
    md5     FixedString(16),
    sha256  FixedString(32)
)"""
        )
        for k in hashes:
            # workaround to a possible bug in the repository structure
            # if files/list/*.hash.* files contain missing packages
            if hashes[k]["md5"] is None:
                continue
            payload.append(
                {"name": k, "md5": hashes[k]["md5"], "sha256": hashes[k]["sha256"]}
            )
        result = self.conn.execute("INSERT INTO PkgHashTmp (*) VALUES", payload)
        self.logger.debug(f"Inserted {len(payload)} hashes into PkgHashTmp")
        # Free memory immediatelly
        del payload

    @Timing.timeit(NAME)
    def update_hases_from_db(self, repo_cache: dict) -> None:
        result = self.conn.execute(
"""
SELECT t1.name, t1.md5, t2.mmh, t2.sha1 
FROM PkgHashTmp AS t1 
LEFT JOIN
(
    SELECT pkgh_md5 AS md5, pkgh_mmh AS mmh, pkgh_sha1 AS sha1
    FROM PackageHash_buffer
) AS t2
ON t1.md5 = t2.md5""",
            settings={"strings_as_bytes": True},
        )
        cnt1 = cnt2 = 0
        if len(result):  # type: ignore
            for (k, *v) in result:  # type: ignore
                if len(v) == 3:
                    kk = k.decode("utf-8")
                    if kk in repo_cache.keys():
                        if v[1] != 0:
                            # repo_cache[kk]['md5'] = v[0]
                            repo_cache[kk]["mmh"] = v[1]
                            repo_cache[kk]["sha1"] = v[2]
                            cnt1 += 1
                        else:
                            repo_cache[kk]["mmh"] = 0
                            repo_cache[kk]["sha1"] = None
                            cnt2 += 1
        self.logger.debug(
            f"Requested {len(result)} package hashes from database. "  # type: ignore
            f"For {len(repo_cache)} packages {cnt1} hashes found in "
            f"'PackagaeHash_buffer' table, {cnt2} packages not loaded yet."
        )

    def check_repo_date_name_in_db(self, pkgset_name: str, pkgset_date: datetime.date) -> bool:
        result = self.conn.execute(
            f"SELECT COUNT(*) FROM PackageSetName WHERE "
            f"pkgset_nodename='{pkgset_name}' AND pkgset_date='{pkgset_date}'"
        )
        return result[0][0] != 0  # type: ignore


def get_hashes_from_pkglist(fname: str) -> tuple[bool, str, dict]:
    hdrs = readHeaderListFromXZFile(fname)
    if fname.split("/")[-1].startswith("srclist"):
        src_list = True
    else:
        src_list = False
    hsh = {}
    for hdr in hdrs:
        pkg_name = cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYFILENAME])
        pkg_md5 = bytes.fromhex(cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYMD5]))
        pkg_blake2b = bytes.fromhex(cvt(hdr[rpm.RPMTAG_APTINDEXLEGACYBLAKE2B]))
        hsh[pkg_name] = (pkg_md5, pkg_blake2b)
    return src_list, fname, hsh


def read_release_components(file: Path) -> list[str]:
    """Read components from 'release' file in reposiory tree."""

    comps = []
    with file.open(mode="r") as fd:
        for line in fd.readlines():
            ls = line.split(":")
            if ls[0] == "Components":
                comps = [x.strip() for x in ls[1].split()]
                break
    return comps


def check_release_for_blake2b(file: Path) -> bool:
    """Search blake2b hashes mentioned in release file in reposiory tree."""

    with file.open(mode="r") as fd:
        for line in fd.readlines():
            ls = line.split(":")
            if ls[0] == "BLAKE2b":
                return True
    return False


def read_repo_structure(repo_name: str, repo_path: str, logger: logging.Logger) -> dict:
    """Reads repository structure for given path and store."""

    repo = {
        "repo": {
            "name": repo_name,
            "uuid": str(uuid4()),
            "puuid": "00000000-0000-0000-0000-000000000000",
            "path": str(Path(repo_path)),
            "kwargs": defaultdict(lambda: None, key=None),
        },
        "src": {"name": "srpm", "uuid": str(uuid4()), "puuid": None, "path": []},
        "arch": {"archs": [], "kwargs": defaultdict(lambda: None, key=None)},
        "comp": {"comps": [], "kwargs": defaultdict(lambda: None, key=None)},
        "src_hashes": defaultdict(lambda: defaultdict(lambda: None, key=None)),
        "pkg_hashes": defaultdict(lambda: defaultdict(lambda: None, key=None)),
        "use_blake2b": False,
        "bin_pkgs": {},
    }

    repo["src"]["puuid"] = repo["repo"]["uuid"]
    repo["arch"]["kwargs"]["all_archs"] = set()
    repo["comp"]["kwargs"]["all_comps"] = set()

    root = Path(repo["repo"]["path"])

    if not Path.joinpath(root, "files/list").is_dir() or not [
        x for x in root.iterdir() if (x.is_dir() and x.name in ARCHS)
    ]:
        raise NotImplementedError(
            message=f"The path '{str(root)}' is not regular repository structure root"
        )

    pkglists = []
    for arch_dir in [_ for _ in root.iterdir() if (_.is_dir() and _.name in ARCHS)]:
        # if arch_dir.is_dir() and arch_dir.name in ARCHS:
        repo["arch"]["archs"].append(
            {
                "name": arch_dir.name,
                "uuid": str(uuid4()),
                "puuid": repo["repo"]["uuid"],
                "path": arch_dir.name,
            }
        )
        repo["arch"]["kwargs"]["all_archs"].add(arch_dir.name)
        # append '%ARCH%/SRPM.classic' path to 'src'
        repo["src"]["path"].append(
            "/".join(arch_dir.joinpath("SRPMS.classic").parts[-2:])
        )
        # check '%ARCH%/base' directory for components
        base_subdir = arch_dir.joinpath("base")
        if base_subdir.is_dir():
            # store components and paths to it
            release_file = base_subdir.joinpath("release")
            for comp_name in read_release_components(release_file):
                repo["comp"]["comps"].append(
                    {
                        "name": comp_name,
                        "uuid": str(uuid4()),
                        "puuid": repo["arch"]["archs"][-1]["uuid"],
                        "path": "/".join(
                            arch_dir.joinpath("RPMS." + comp_name).parts[-2:]
                        ),
                    }
                )
                repo["comp"]["kwargs"]["all_comps"].add(comp_name)
            # load MD5 from '%ARCH%/base/[pkg|src]list.%COMP%.xz'
            pkglist_names = ["srclist.classic"]
            pkglist_names += [
                ("pkglist." + _) for _ in repo["comp"]["kwargs"]["all_comps"]
            ]
            for pkglist_name in pkglist_names:
                f = base_subdir.joinpath(pkglist_name + ".xz")
                if f.is_file():
                    pkglists.append(str(f))
            # check if blake2b hashes used by release file contents
            if not repo["use_blake2b"]:
                repo["use_blake2b"] = check_release_for_blake2b(release_file)

    # get hashes from header lists with multiprocessing
    logger.info(f"Reading package's hashes from headers lists")
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as p:
        for res in p.map(get_hashes_from_pkglist, pkglists):
            logger.info(f"Got {len(res[2])} package hashes from {res[1]}")
            if res[0]:
                for k, v in res[2].items():
                    repo["src_hashes"][k]["md5"] = v[0]
                    repo["src_hashes"][k]["blake2b"] = v[1]
            else:
                # store binary packages by arch and component
                arch_ = res[1].split("/")[-3]
                comp_ = res[1].split(".")[-2]
                repo["bin_pkgs"][(arch_, comp_)] = tuple(res[2].keys())
                # store hashes
                for k, v in res[2].items():
                    repo["pkg_hashes"][k]["md5"] = v[0]
                    repo["pkg_hashes"][k]["blake2b"] = v[1]

    # check if '%root%/files/list' exists and load all data from it
    p = root.joinpath("files/list")
    if p.is_dir():
        # load task info
        f = Path.joinpath(p, "task.info")
        if f.is_file():
            contents = (_ for _ in f.read_text().split("\n") if len(_))
            for c in contents:
                k, v = c.split()
                repo["repo"]["kwargs"][k] = v

        # load all SHA256 hashes
        for arch in ARCHS:
            f = p.joinpath(arch + ".hash.xz")
            if f.is_file():
                contents = (x for x in unxz(f, mode_binary=False).split("\n") if len(x))  # type: ignore
                if arch == "src":
                    # load to src_hashes
                    for c in contents:
                        pkg_name = c.split()[1]
                        pkg_sha256 = bytes.fromhex(c.split()[0])  # type: ignore
                        # calculate and store missing MD5 hashes for 'src.rpm'
                        # TODO: workaround for missing/unhandled src.gostcrypto.xz
                        if pkg_name not in repo["src_hashes"]:
                            logger.info(
                                f"{pkg_name}'s MD5 not found. Calculating it from file"
                            )
                            # calculate missing MD5 from file here
                            f = root.joinpath("files", "SRPMS", pkg_name)  # type: ignore
                            if f.is_file():
                                pkg_md5 = md5_from_file(f, as_bytes=True)
                                repo["src_hashes"][pkg_name]["md5"] = pkg_md5
                            else:
                                logger.error(
                                    f"Cant find file to calculate MD5 for {pkg_name} "
                                    f"from {root.joinpath('files, ''SRPMS')}"
                                )
                                # raise RuntimeError("File not found")
                                pass  # FIXME: workaround for mipsel branches
                        repo["src_hashes"][pkg_name]["sha256"] = pkg_sha256
                else:
                    # load to pkg_hashes
                    for c in contents:
                        pkg_name = c.split()[1]
                        pkg_sha256 = bytes.fromhex(c.split()[0])  # type: ignore
                        repo["pkg_hashes"][pkg_name]["sha256"] = pkg_sha256
        # find packages with SHA256 or blake2b hash missing and calculate it from file
        # for source files
        for k, v in repo["src_hashes"].items():
            if v["sha256"] is None:
                logger.info(f"{k}'s SHA256 not found. Calculating it from file")
                file_ = root.joinpath("files", "SRPMS", k)
                if file_.is_file():
                    repo["src_hashes"][k]["sha256"] = sha256_from_file(
                        file_, as_bytes=True
                    )
                else:
                    logger.error(
                        f"Can't find file to calculate SHA256 "
                        f"for {file_.name} from {file_.parent}"
                    )
                    raise RuntimeError("File not found")
            if v["blake2b"] in (b"", None) and repo["use_blake2b"]:
                logger.info(f"{k}'s blake2b not found. Calculating it from file")
                file_ = root.joinpath("files", "SRPMS", k)
                if file_.is_file():
                    repo["src_hashes"][k]["blake2b"] = blake2b_from_file(
                        file_, as_bytes=True
                    )
                else:
                    logger.error(
                        f"Can't find file to calculate blake2b "
                        f"for {file_.name} from {file_.parent}"
                    )
                    raise RuntimeError("File not found")
        # for binary files
        for k, v in repo["pkg_hashes"].items():
            file_ = Path()
            if v["sha256"] is None:
                logger.info(f"{k}'s SHA256 not found. Calculating it from file")
                found_ = False
                for arch in repo["arch"]["kwargs"]["all_archs"]:
                    file_ = root.joinpath("files", arch, "RPMS", k)
                    if file_.is_file():
                        repo["pkg_hashes"][k]["sha256"] = sha256_from_file(
                            file_, as_bytes=True
                        )
                        found_ = True
                        break
                if not found_:
                    logger.error(
                        f"Can't find file to calculate SHA256 "
                        f"for {file_.name} from {file_.parent}"
                    )
                    raise RuntimeError("File not found")
            if v["blake2b"] in (b"", None) and repo["use_blake2b"]:
                logger.info(f"{k}'s blake2b not found. Calculating it from file")
                found_ = False
                for arch in repo["arch"]["kwargs"]["all_archs"]:
                    file_ = root.joinpath("files", arch, "RPMS", k)
                    if file_.is_file():
                        repo["pkg_hashes"][k]["blake2b"] = blake2b_from_file(
                            file_, as_bytes=True
                        )
                        found_ = True
                        break
                if not found_:
                    logger.error(
                        f"Can't find file to calculate blake2b "
                        f"for {file_.name} from {file_.parent}"
                    )
                    raise RuntimeError("File not found")

    logger.debug(f"Found {len(repo['src']['path'])} source directories")
    logger.debug(
        f"Found {len(repo['comp']['comps'])} components "
        f"for {len(repo['arch']['archs'])} architectures"
    )
    logger.debug(f"Found {len(repo['src_hashes'])} hashes for 'src.rpm' files")
    logger.debug(f"Found {len(repo['pkg_hashes'])} hashes for 'rpm' files")

    return repo


def load(args: Any, logger: logging.Logger):
    conn = get_client(args)
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
        kv_args=tmp_d,
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
            kv_args=tmp_d,
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
            kv_args=tmp_d,
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
        kv_args=tmp_d,
    )

    for c in connections:
        if c is not None:
            c.disconnect()

    if display is not None:
        display.conclusion()


def get_args():
    parser = argparse.ArgumentParser(
        prog="extract",
        description="Load repository structure from file system or ISO image to database",
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
        logger.error(error, exc_info=True)
    finally:
        logger.info("stop loading packages")


if __name__ == "__main__":
    main()
