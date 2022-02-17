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

import rpm
import time
import base64
import datetime
import itertools
import threading
import multiprocessing
from uuid import uuid4
from pathlib import Path
from collections import namedtuple
from dataclasses import asdict
from multiprocessing import Process, Queue
from typing import Any, Iterable, Optional, Union

import altrepodb.mapper as mapper
from altrpm import rpm as rpmt, extractSpecFromRPM, readHeaderListFromXZFile
from .utils import (
    cvt,
    unxz,
    md5_from_file,
    sha256_from_file,
    blake2b_from_file,
    calculate_sha256_blake2b,
    check_package_in_cache,
    join_dicts_with_as_string,
    Display,
)
from .base import (
    DEFAULT_LOGGER,
    _StringOrPath,
    PkgHash,
    RepoLeaf,
    Repository,
    SrcRepoLeaf,
    RootRepoLeaf,
    LockedIterator,
    DatabaseConfig,
    LoggerProtocol,
    RepoProcessorConfig,
)
from .exceptions import PackageLoadError, RepoParsingError, RepoProcessingError
from .database import DatabaseClient
from .misc import lut

NAME = "repo"
MAX_WORKERS_FOR_SRPM = 4


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

    def _extract_spec_file(self, fname):
        """Extracts spec file from SRPM using subprocess to force memory releasing."""

        def _extract_spec_sp(fname: str, q: Queue):
            q.put(extractSpecFromRPM(fname, raw=True))

        q= Queue()
        p = Process(target=_extract_spec_sp, args=(fname, q))
        p.start()
        spec_file, spec_contents = q.get()
        p.join

        return spec_file, spec_contents

    def insert_specfile(self, pkg_file, pkg_map):
        self.logger.debug(f"extracting spec file form {pkg_map['pkg_filename']}")
        st = time.time()
        spec_file, spec_contents = self._extract_spec_file(pkg_file)
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

    def insert_file(self, pkghash, hdr):
        map_file = mapper.get_file_map(hdr)
        map_file["pkg_hash"] = itertools.cycle([pkghash])
        data = mapper.unpack_map(map_file)
        self.conn.execute(
            "INSERT INTO Files_insert ({0}) VALUES".format(", ".join(map_file.keys())),
            data,
        )
        self.logger.debug("insert file for pkghash: {0}".format(pkghash))

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

    @staticmethod
    def convert_hashes(pkghash: PkgHash) -> dict[str, Union[int, bytes]]:
        """Convert PkgHash instance to dictionary for compatibility."""

        hashes = asdict(pkghash)
        hashes["mmh"] = hashes["sf"]
        del hashes["sf"]
        return hashes

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

    def insert_pkgset_name(
        self,
        name: str,
        uuid: str,
        puuid: str,
        ruuid: str,
        depth: int,
        tag: str,
        date: Optional[datetime.datetime],
        complete: int,
        kw_args: dict[str, str],
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
            "pkgset_kv.k": [k for k, v in kw_args.items() if v is not None],
            "pkgset_kv.v": [v for k, v in kw_args.items() if v is not None],
        }
        self.conn.execute(sql, [data])
        self.logger.debug("insert package set name uuid: {0}".format(uuid))

    def insert_pkgset(self, uuid: str, pkghash: Union[list[int], set[int]]) -> None:
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
        src_hashes: dict[str, PkgHash],
        bin_hashes: dict[str, PkgHash],
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
        self.src_hashes = src_hashes
        self.bin_hashes = bin_hashes
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
                        self.src_hashes[pkg_filename].sf = map_package["pkg_hash"]
                        self.src_hashes[pkg_filename].sha1 = map_package["pkg_cs"]
                        # set source rpm name and hash to self
                        kw["pkg_sourcerpm"] = pkg_filename
                        kw["pkg_srcrpm_hash"] = map_package["pkg_hash"]
                        # check if BLAKE2b hash found and if not, calculate it from file
                        if self.src_hashes[pkg_filename].blake2b in (b"", None):
                            self.logger.debug(
                                f"calculate BLAKE2b for {pkg_filename} file"
                            )
                            self.src_hashes[pkg_filename].blake2b = blake2b_from_file(package)
                    else:
                        #  store pkg mmh and sha1
                        self.bin_hashes[pkg_filename].sf = map_package["pkg_hash"]
                        self.bin_hashes[pkg_filename].sha1 = map_package["pkg_cs"]
                        # set source rpm name and hash
                        if map_package["pkg_sourcerpm"] in self.src_hashes:
                            kw["pkg_srcrpm_hash"] = self.src_hashes[map_package["pkg_sourcerpm"]].sf
                        else:
                            kw["pkg_srcrpm_hash"] = None
                        # check if BLAKE2b hash found and if not, calculate it from file
                        if self.bin_hashes[pkg_filename].blake2b in (b"", None):
                            self.logger.debug(
                                f"calculate BLAKE2b for {pkg_filename} file"
                            )
                            self.bin_hashes[pkg_filename].blake2b = blake2b_from_file(package)

                # check if 'pkg_srcrpm_hash' is None - it's Ok for 'x86_64-i586'
                if (
                    map_package["pkg_arch"] == "x86_64-i586"
                    and kw["pkg_srcrpm_hash"] is None
                ):
                    kw["pkg_srcrpm_hash"] = 0

                self.logger.debug(f"processing: {package}")
                pkghash = check_package_in_cache(self.cache, map_package["pkg_hash"])

                if pkghash is None:
                    pkghash = self.ph.insert_package(header, package, **kw)
                    self.cache.add(pkghash)
                    # insert package hashes to PackageHash_buffer
                    if self.is_src:
                        self.ph.insert_pkg_hash_single(
                            self.ph.convert_hashes(self.src_hashes[pkg_filename])
                        )
                    else:
                        self.ph.insert_pkg_hash_single(
                            self.ph.convert_hashes(self.bin_hashes[pkg_filename])
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


def package_load_worker_pool(
    logger: LoggerProtocol,
    repo: Repository,
    is_src: bool,
    pkgset: set,
    pkg_cache: set,
    packages_list: Iterable,
    display: Union[Display, None],
    config: RepoProcessorConfig,
):
    lock = threading.Lock()
    workers: list[Worker] = []
    connections: list[DatabaseClient] = []

    packages = LockedIterator((pkg for pkg in packages_list))

    # limit workers number when dealing with SRPM to reduce
    # memory footprint while extracting spec files
    if is_src:
        num_of_workers = MAX_WORKERS_FOR_SRPM
    else:
        num_of_workers = config.workers

    for i in range(num_of_workers):
        conn = DatabaseClient(config=config.dbconfig, logger=logger)
        connections.append(conn)
        worker = Worker(
            connection=conn,
            logger=logger,
            lock=lock,
            pkg_cache=pkg_cache,
            src_hashes=repo.src_hashes,
            bin_hashes=repo.bin_hashes,
            packages=packages,
            pkgset=pkgset,
            display=display,
            is_src=is_src,
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


class RepoLoadHelper:
    """Helper for repository structure processing and loading to DB."""

    def __init__(self, conn: DatabaseClient, logger: LoggerProtocol):
        self.conn = conn
        self.logger = logger

    @staticmethod
    def init_cache(src_hashes: dict[str, PkgHash], bin_hashes: dict[str, PkgHash]) -> set[int]:
        cache = set()
        for v in src_hashes.values():
            if v.sf not in (0, None):
                cache.add(v.sf)
        for v in bin_hashes.values():
            if v.sf not in (0, None):
                cache.add(v.sf)

        return cache

    def init_hash_temp_table(self, hashes: dict[str, PkgHash]) -> None:
        payload = []
        result = self.conn.execute(
"""
CREATE TEMPORARY TABLE IF NOT EXISTS _tmpPkgHash
(
    name    String,
    md5     FixedString(16),
    sha256  FixedString(32)
)"""
        )
        for k in hashes:
            # workaround to a possible bug in the repository structure
            # if files/list/*.hash.* files contain missing packages
            if hashes[k].md5 is None:
                continue
            payload.append(
                {"name": k, "md5": hashes[k].md5, "sha256": hashes[k].sha256}
            )
        result = self.conn.execute("INSERT INTO _tmpPkgHash (*) VALUES", payload)
        self.logger.debug(f"Inserted {len(payload)} hashes into _tmpPkgHash")
        # Free memory immediatelly
        del payload

    def update_hases_from_db(self, repo_cache: dict[str, PkgHash]) -> None:
        result = self.conn.execute(
"""
SELECT t1.name, t1.md5, t2.mmh, t2.sha1 
FROM _tmpPkgHash AS t1 
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
                            repo_cache[kk].sf = v[1]
                            repo_cache[kk].sha1 = v[2]
                            cnt1 += 1
                        else:
                            repo_cache[kk].sf = 0
                            repo_cache[kk].sha1 = None
                            cnt2 += 1
        self.logger.debug(
            f"Requested {len(result)} package hashes from database. "  # type: ignore
            f"For {len(repo_cache)} packages {cnt1} hashes found in "
            f"'PackagaeHash_buffer' table, {cnt2} packages not loaded yet."
        )

    def check_repo_date_name_in_db(
        self, pkgset_name: str, pkgset_date: datetime.date
    ) -> bool:
        result = self.conn.execute(
            f"SELECT COUNT(*) FROM PackageSetName WHERE "
            f"pkgset_nodename='{pkgset_name}' AND pkgset_date='{pkgset_date}'"
        )
        return result[0][0] != 0  # type: ignore


PkglistResult = namedtuple("PkglistResult", ["is_src", "fname", "hashes"])


def get_hashes_from_pkglist(fname: str) -> PkglistResult:
    """Read package's hashes from compressed APT headers list files."""

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
    return PkglistResult(src_list, fname, hsh)


class RepoParser:
    """Read and parse repository structure."""

    def __init__(self, repo_name: str, repo_path: _StringOrPath, logger: LoggerProtocol) -> None:
        self.name = repo_name
        self.path = Path(repo_path)
        self.logger = logger
        self.pkglists: list[str]
        self.repo = self._init_repo_structure()

    def _init_repo_structure(self):
        """Check if repository structure is valid and init self.repo instance."""

        if not Path.joinpath(self.path, "files/list").is_dir() or not [
            x for x in self.path.iterdir() if (x.is_dir() and x.name in lut.ARCHS)
        ]:
            raise RepoParsingError(
                f"The path '{str(self.path)}' is not regular repository structure root"
            )

        repo = Repository(
            root = RootRepoLeaf(
                name=self.name,
                path=str(self.path),
                uuid=str(uuid4()),
                puuid="00000000-0000-0000-0000-000000000000",
                kwargs=dict(),
            ),
            src=SrcRepoLeaf(
                name="srpm",
                path=list(),
                uuid=str(uuid4()),
                puuid=""
            ),
            archs=list(),
            comps=list(),
            src_hashes=dict(),
            bin_hashes=dict(),
            bin_pkgs=dict(),
            use_blake2b=False
        )
        repo.src.puuid = repo.root.uuid
        repo.root.kwargs["class"] = "repository"

        return repo

    def _collect_parts(self):
        """Collect repository archs and components parts."""

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

        self.pkglists = []
        for arch_dir in [_ for _ in self.path.iterdir() if (_.is_dir() and _.name in lut.ARCHS)]:
            self.repo.archs.append(
                RepoLeaf(
                    name=arch_dir.name,
                    path=arch_dir.name,
                    uuid=str(uuid4()),
                    puuid=self.repo.root.uuid,
                )
            )
            # append '%ARCH%/SRPM.classic' path to 'src'
            self.repo.src.path.append(
                "/".join(arch_dir.joinpath("SRPMS.classic").parts[-2:])
            )
            # check '%ARCH%/base' directory for components
            base_subdir = arch_dir.joinpath("base")
            if base_subdir.is_dir():
                # store components and paths to it
                release_file = base_subdir.joinpath("release")
                for comp_name in read_release_components(release_file):
                    self.repo.comps.append(
                        RepoLeaf(
                            name=comp_name,
                            path="/".join(
                                arch_dir.joinpath("RPMS." + comp_name).parts[-2:]
                            ),
                            uuid=str(uuid4()),
                            puuid=self.repo.archs[-1].uuid,
                        )
                    )
                # collect package lists from '%ARCH%/base/[pkg|src]list.%COMP%.xz'
                pkglist_names = ["srclist.classic"]
                pkglist_names += [("pkglist." + comp) for comp in self.repo.all_comps]
                for pkglist_name in pkglist_names:
                    f = base_subdir.joinpath(pkglist_name + ".xz")
                    if f.is_file():
                        self.pkglists.append(str(f))
                # check if blake2b hashes used by release file contents
                def check_release_for_blake2b(file: Path) -> bool:
                    """Search BLAKE2b hashes mentioned in release file from reposiory tree."""

                    with file.open(mode="r") as fd:
                        for line in fd.readlines():
                            ls = line.split(":")
                            if ls[0] == "BLAKE2b":
                                return True
                    return False

                if not self.repo.use_blake2b:
                    self.repo.use_blake2b = check_release_for_blake2b(release_file)

    def _get_hashes_from_package_lists(self):
        """Get package's hashes from header lists with multiprocessing."""

        self.logger.info(f"Reading package's hashes from headers lists")
        with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as p:
            for pkglist in p.map(get_hashes_from_pkglist, self.pkglists):
                self.logger.info(f"Got {len(pkglist.hashes)} package hashes from {pkglist.fname}")
                if pkglist.is_src:
                    for k, v in pkglist.hashes.items():
                        if k not in self.repo.src_hashes:
                            self.repo.src_hashes[k] = PkgHash()
                        self.repo.src_hashes[k].md5 = v[0]
                        self.repo.src_hashes[k].blake2b = v[1]
                else:
                    # store binary packages by arch and component
                    arch_ = pkglist.fname.split("/")[-3]
                    comp_ = pkglist.fname.split(".")[-2]
                    self.repo.bin_pkgs[(arch_, comp_)] = tuple(pkglist.hashes.keys())
                    # store hashes
                    for k, v in pkglist.hashes.items():
                        if k not in self.repo.bin_hashes:
                            self.repo.bin_hashes[k] = PkgHash()
                        self.repo.bin_hashes[k].md5 = v[0]
                        self.repo.bin_hashes[k].blake2b = v[1]

    def _parse_files_lists(self):
        """Check if '%root%/files/list' exists and load all data from it."""

        p = self.path.joinpath("files/list")
        if not p.is_dir():
            return
        # load task info
        f = Path.joinpath(p, "task.info")
        if f.is_file():
            contents = (x for x in f.read_text().split("\n") if len(x))
            for c in contents:
                k, v = c.split()
                self.repo.root.kwargs[k] = v

        # load all SHA256 hashes
        for arch in lut.ARCHS:
            f = p.joinpath(arch + ".hash.xz")
            if not f.is_file():
                continue
            contents = (x for x in unxz(f, mode_binary=False).split("\n") if len(x))  # type: ignore
            if arch == "src":
                # load to src_hashes
                for c in contents:
                    pkg_name: str = c.split()[1]  # type: ignore
                    pkg_sha256 = bytes.fromhex(c.split()[0])  # type: ignore
                    # calculate and store missing MD5 hashes for 'src.rpm'
                    # TODO: workaround for missing/unhandled src.gostcrypto.xz
                    if pkg_name not in self.repo.src_hashes:
                        self.repo.src_hashes[pkg_name] = PkgHash()
                        self.logger.info(
                            f"{pkg_name}'s MD5 not found. Calculating it from file"
                        )
                        # calculate missing MD5 from file here
                        f = self.path.joinpath("files", "SRPMS", pkg_name)  # type: ignore
                        if f.is_file():
                            pkg_md5 = md5_from_file(f)
                            self.repo.src_hashes[pkg_name].md5 = pkg_md5
                        else:
                            self.logger.warning(
                                f"Cant find file to calculate MD5 for {pkg_name} "
                                f"from {self.path.joinpath('files, ''SRPMS')}"
                            )
                            # raise RuntimeError("File not found")
                            pass  # FIXME: workaround for mipsel branches
                    self.repo.src_hashes[pkg_name].sha256 = pkg_sha256
            else:
                # load to bin_hashes
                for c in contents:
                    pkg_name = c.split()[1]  # type: ignore
                    pkg_sha256 = bytes.fromhex(c.split()[0])  # type: ignore
                    if pkg_name not in self.repo.bin_hashes:
                        self.repo.bin_hashes[pkg_name] = PkgHash()
                    self.repo.bin_hashes[pkg_name].sha256 = pkg_sha256
        # find packages with SHA256 or blake2b hash missing and calculate it from file
        # for source files
        for k, v in self.repo.src_hashes.items():
            if (v.sha256 in (b"", None) or (v.blake2b in (b"", None) and self.repo.use_blake2b)):
                self.logger.info(f"{k}'s SHA256 or BLAKE2b hash not found. Calculating it from file")
            else:
                continue

            pkg_file = self.path.joinpath("files", "SRPMS", k)
            if not pkg_file.is_file():
                self.logger.error(
                    f"Can't find file to calculate hashes "
                    f"for {pkg_file.name} from {pkg_file.parent}"
                )
                raise RepoParsingError(f"File not found: {pkg_file}")

            (
                self.repo.src_hashes[k].sha256,
                self.repo.src_hashes[k].blake2b
            ) = calculate_sha256_blake2b(pkg_file, v.sha256, v.blake2b, self.repo.use_blake2b)
        # for binary files
        pkg_file = Path()  # initialized just for type checking
        for k, v in self.repo.bin_hashes.items():
            if (v.sha256 in (b"", None) or (v.blake2b in (b"", None) and self.repo.use_blake2b)):
                self.logger.info(f"{k}'s SHA256 or BLAKE2b hash not found. Calculating it from file")
            else:
                continue

            found = False
            for arch in self.repo.all_archs:
                pkg_file = self.path.joinpath("files", arch, "RPMS", k)
                if pkg_file.is_file():
                    (
                        self.repo.bin_hashes[k].sha256,
                        self.repo.bin_hashes[k].blake2b
                    ) = calculate_sha256_blake2b(pkg_file, v.sha256, v.blake2b, self.repo.use_blake2b)
                    found = True
                    break
            if not found:
                self.logger.error(
                    f"Can't find file to calculate hashes "
                    f"for {pkg_file.name} from {pkg_file.parent}"
                )
                raise RepoParsingError(f"File not found: {pkg_file}")

    def parse_repository(self):
        self._collect_parts()
        self._get_hashes_from_package_lists()
        self._parse_files_lists()

        self.logger.debug(f"Found {len(self.repo.src.path)} source directories")
        self.logger.debug(
            f"Found {len(self.repo.comps)} components "
            f"for {len(self.repo.archs)} architectures"
        )
        self.logger.debug(f"Found {len(self.repo.src_hashes)} hashes for 'src.rpm' files")
        self.logger.debug(f"Found {len(self.repo.bin_hashes)} hashes for 'rpm' files")


class RepoLoadHandler:
    """Handles repository structure loading to DB."""

    def __init__(self, config: RepoProcessorConfig, logger: LoggerProtocol) -> None:
        self.config = config
        self.logger = logger
        self.cache = set()
        self.repo : Repository
        self.conn = DatabaseClient(config=self.config.dbconfig, logger=self.logger)
        self.rlh = RepoLoadHelper(conn=self.conn, logger=self.logger)
        self.psh = PackageSetHandler(conn=self.conn, logger=self.logger)

        self.display = None
        if self.config.verbose:
            self.display = Display(log=self.logger)


    def check_repo_in_db(self):
        if self.rlh.check_repo_date_name_in_db(self.config.name, self.config.date.date()):
            if not self.config.force:
                self.logger.error(
                    f"Repository with name '{self.config.name}' and "
                    f"date '{self.config.date.date()}' already exists in database"
                )
                raise RepoProcessingError("Package set is already loaded to DB!")

    def _init_cache(self):
        self.rlh.init_hash_temp_table(self.repo.src_hashes)
        self.rlh.init_hash_temp_table(self.repo.bin_hashes)
        self.rlh.update_hases_from_db(self.repo.src_hashes)
        self.rlh.update_hases_from_db(self.repo.bin_hashes)
        self.cache = self.rlh.init_cache(self.repo.src_hashes, self.repo.bin_hashes)

    def _load_srpms(self):
        # level 1 : src
        # load source RPMs first
        # generate 'src.rpm' packages list
        ts = time.time()
        pkg_count = 0
        pkg_count2 = 0
        pkgset = set()
        pkgset_cached = set()
        packages_list = []
        self.logger.info("Start checking SRC packages")
        # load source packages fom 'files/SRPMS'
        src_dir = Path(self.config.path).joinpath("files/SRPMS")
        if not src_dir.is_dir():
            raise RepoProcessingError(f"'/files/SRPMS' directory not found")
        self.logger.info(f"Start checking SRC packages in {'/'.join(src_dir.parts[-2:])}")
        for pkg in self.repo.src_hashes:
            pkg_count += 1
            if self.repo.src_hashes[pkg].sha1 is None:
                rpm_file = src_dir.joinpath(pkg)
                if not rpm_file.is_file():
                    raise RepoProcessingError(f"File {rpm_file} not found")
                packages_list.append(str(rpm_file))
            else:
                pkgh = self.repo.src_hashes[pkg].sf
                if not pkgh:
                    raise RepoProcessingError(f"No hash found in cache for {pkg}")
                pkgset_cached.add(pkgh)
                pkg_count2 += 1
        self.logger.info(
            f"Checked {pkg_count} SRC packages. "
            f"{pkg_count2} packages in cache, "
            f"{len(packages_list)} packages for load. "
            f"Time elapsed {(time.time() - ts):.3f} sec."
        )
        # load 'src.rpm' packages
        package_load_worker_pool(
            is_src=True,
            repo=self.repo,
            pkgset=pkgset,
            pkg_cache=self.cache,
            packages_list=packages_list,
            config=self.config,
            logger=self.logger,
            display=self.display,
        )
        # build pkgset for PackageSet record
        pkgset.update(pkgset_cached)

        self.psh.insert_pkgset(self.repo.src.uuid, pkgset)
        # store PackageSetName record for 'src'
        tmp_d = {"depth": "1", "type": "srpm", "size": str(len(pkgset))}
        tmp_d = join_dicts_with_as_string(tmp_d, self.repo.root.kwargs["class"], "class")
        tmp_d = join_dicts_with_as_string(tmp_d, self.repo.src.path, "SRPMS")
        tmp_d = join_dicts_with_as_string(tmp_d, self.repo.root.name, "repo")
        self.psh.insert_pkgset_name(
            name=self.repo.src.name,
            uuid=self.repo.src.uuid,
            puuid=self.repo.src.puuid,
            ruuid=self.repo.root.uuid,
            depth=1,
            tag=self.config.tag,
            date=self.config.date,
            complete=1,
            kw_args=tmp_d,
        )

    def _load_architectures(self):
        for arch in self.repo.archs:
            tmp_d = {"depth": "1", "type": "arch", "size": "0"}
            tmp_d = join_dicts_with_as_string(tmp_d, self.repo.root.kwargs["class"], "class")
            tmp_d = join_dicts_with_as_string(tmp_d, arch.path, "path")
            tmp_d = join_dicts_with_as_string(tmp_d, self.repo.root.name, "repo")
            self.psh.insert_pkgset_name(
                name=arch.name,
                uuid=arch.uuid,
                puuid=arch.puuid,
                ruuid=self.repo.root.uuid,
                depth=1,
                tag=self.config.tag,
                date=self.config.date,
                complete=1,
                kw_args=tmp_d,
            )

    def _load_components(self):
        for comp in self.repo.comps:
            # load RPMs first
            ts = time.time()
            pkg_count = 0
            pkgset = set()
            pkgset_cached = set()
            packages_list = []
            # generate 'rpm' packages list
            self.logger.info(f"Start checking RPM packages in '{comp.path}'")
            rpm_dir = Path(self.config.path).joinpath(comp.path)
            # proceed binary packages using repo["bin_pkgs"] dictionary
            arch_ = comp.path.split("/")[0]
            comp_ = comp.path.split(".")[-1]
            for pkg in self.repo.bin_pkgs[(arch_, comp_)]:
                rpm_file = rpm_dir.joinpath(pkg)
                pkg_count += 1
                if self.repo.bin_hashes[pkg].sha1 is None:
                    if not rpm_file.is_file():
                        raise ValueError(f"File {pkg} not found in {comp.path}")
                    packages_list.append(str(rpm_file))
                else:
                    pkgh = self.repo.bin_hashes[rpm_file.name].sf
                    if not pkgh:
                        raise ValueError(f"No hash found in cache for {pkg}")
                    pkgset_cached.add(pkgh)
            self.logger.info(
                f"Checked {pkg_count} RPM packages. "
                f"{len(packages_list)} packages for load. "
                f"Time elapsed {(time.time() - ts):.3f} sec."
            )
            # load '.rpm' packages
            package_load_worker_pool(
                is_src=False,
                repo=self.repo,
                pkgset=pkgset,
                pkg_cache=self.cache,
                packages_list=packages_list,
                config=self.config,
                logger=self.logger,
                display=self.display,
            )
            # build pkgset for PackageSet record
            pkgset.update(pkgset_cached)

            self.psh.insert_pkgset(comp.uuid, pkgset)
            # store PackageSetName record
            tmp_d = {"depth": "2", "type": "comp", "size": str(len(pkgset))}
            tmp_d = join_dicts_with_as_string(tmp_d, self.repo.root.kwargs["class"], "class")
            tmp_d = join_dicts_with_as_string(tmp_d, comp.path, "path")
            tmp_d = join_dicts_with_as_string(tmp_d, self.repo.root.name, "repo")
            self.psh.insert_pkgset_name(
                name=comp.name,
                uuid=comp.uuid,
                puuid=comp.puuid,
                ruuid=self.repo.root.uuid,
                depth=2,
                tag=self.config.tag,
                date=self.config.date,
                complete=1,
                kw_args=tmp_d,
            )

    def _load_root(self):
        tmp_d = {
            "depth": "0",
            "type": "repo",
            "size": str(len(self.repo.src_hashes) + len(self.repo.bin_hashes)),
        }
        tmp_d = join_dicts_with_as_string(tmp_d, self.repo.root.kwargs, None)
        tmp_d = join_dicts_with_as_string(tmp_d, list(self.repo.all_archs), "archs")
        tmp_d = join_dicts_with_as_string(tmp_d, list(self.repo.all_comps), "comps")
        self.psh.insert_pkgset_name(
            name=self.repo.root.name,
            uuid=self.repo.root.uuid,
            puuid=self.repo.root.puuid,
            ruuid=self.repo.root.uuid,
            depth=0,
            tag=self.config.tag,
            date=self.config.date,
            complete=1,
            kw_args=tmp_d,
        )

    def upload(self, repo: Repository, ):
        self.repo = repo
        try:
            self._init_cache()
            self._load_srpms()
            self._load_architectures()
            self._load_components()
            self._load_root()
            if self.display is not None:
                self.display.conclusion()
        except Exception as e:
            raise e
        finally:
            self.conn.disconnect()


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
