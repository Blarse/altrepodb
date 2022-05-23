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

import multiprocessing as mp
from uuid import uuid4
from typing import Union
from pathlib import Path
from collections import namedtuple

from altrpm import rpm as rpmt, readHeaderListFromXZFile
from altrepodb.misc import lut
from altrepodb.utils import cvt, md5_from_file, calculate_sha256_blake2b
from altrepodb.logger import LoggerProtocol

from .base import PkgHash, Repository, RepoLeaf, SrcRepoLeaf, RootRepoLeaf
from .exceptions import RepoParsingError

_StringOrPath = Union[str, Path]

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
        self.pkglists: list[str] = []
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
            root=RootRepoLeaf(
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
        with mp.Pool(processes=mp.cpu_count()) as p:
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
                    # XXX: workaround for missing/unhandled src.gostcrypto.xz
                    if pkg_name not in self.repo.src_hashes:
                        self.logger.info(
                            f"{pkg_name}'s MD5 not found. Calculating it from file"
                        )
                        # calculate missing MD5 from file here
                        f = self.path.joinpath("files", "SRPMS", pkg_name)  # type: ignore
                        if f.is_file():
                            self.repo.src_hashes[pkg_name] = PkgHash()
                            pkg_md5 = md5_from_file(f)
                            self.repo.src_hashes[pkg_name].md5 = pkg_md5
                        else:
                            self.logger.warning(
                                f"Cant find file to calculate MD5 for {pkg_name} "
                                f"from {self.path.joinpath('files, ''SRPMS')}"
                            )
                            # raise RuntimeError("File not found")
                            # FIXME: workaround for mipsel and e2k branches with
                            # extra SRPMs in Depot hash lists
                            continue
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
        pkg_file = Path()
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
