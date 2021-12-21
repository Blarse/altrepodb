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

import rpm
import time
import base64
import datetime
import itertools
import threading
import multiprocessing
from uuid import uuid4
from pathlib import Path
from collections import defaultdict
from typing import Any, Iterable, Union

import altrepodb.mapper as mapper
from altrpm import rpm as rpmt, extractSpecFromRPM, readHeaderListFromXZFile
from altrepodb.utils import (
    cvt,
    unxz,
    md5_from_file,
    sha256_from_file,
    blake2b_from_file,
    check_package_in_cache,
    Timing,
    Display,
)
from altrepodb.base import LockedIterator, DatabaseConfig, LoggerProtocol
from altrepodb.exceptions import NotImplementedError, PackageLoadError
from altrepodb.database import DatabaseClient
from altrepodb.misc import lut

NAME = "repo"

class PackageHandler:
    """Handle package header parsing and insertion to DB."""

    def __init__(self, conn: DatabaseClient, logger: LoggerProtocol):
        self.conn = conn
        self.logger = logger

    @staticmethod
    def get_header(rpmfile: str) -> Any:
        # return readHeaderFromRPM(rpmfile)
        ts = rpm.TransactionSet()
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

    def __init__(self, conn: DatabaseClient, logger: LoggerProtocol):
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
        connection: DatabaseClient,
        logger: LoggerProtocol,
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
                self.logger.error(str(error), exc_info=True)
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
    logger: LoggerProtocol,
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
    connections: list[DatabaseClient] = []

    packages = LockedIterator((pkg for pkg in packages_list))

    db_config = DatabaseConfig(
        host=args.host,
        port=args.port,
        name=args.dbname,
        user=args.user,
        password=args.password
    )

    for i in range(args.workers):
        conn = DatabaseClient(
            config=db_config,
            logger=logger
        )
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

    def __init__(self, conn: DatabaseClient, logger: LoggerProtocol):
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
        pkg_name = cvt(hdr[rpmt.RPMTAG_APTINDEXLEGACYFILENAME])
        pkg_md5 = bytes.fromhex(cvt(hdr[rpmt.RPMTAG_APTINDEXLEGACYMD5]))
        pkg_blake2b = bytes.fromhex(cvt(hdr[rpmt.RPMTAG_APTINDEXLEGACYBLAKE2B]))
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


def read_repo_structure(repo_name: str, repo_path: str, logger: LoggerProtocol) -> dict:
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
        x for x in root.iterdir() if (x.is_dir() and x.name in lut.ARCHS)
    ]:
        raise NotImplementedError(
            message=f"The path '{str(root)}' is not regular repository structure root"
        )

    pkglists = []
    for arch_dir in [_ for _ in root.iterdir() if (_.is_dir() and _.name in lut.ARCHS)]:
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
        for arch in lut.ARCHS:
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
