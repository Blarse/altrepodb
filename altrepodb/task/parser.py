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

import logging
import datetime
from collections import defaultdict

from altrepodb.altrpm import rpm as rpmt, readHeaderListFromXZFile
from altrepodb.base import PkgHash, PkgInfo
from altrepodb.utils import md5_from_file
from altrepodb.utils import val_from_json_str
from altrepodb.repo.utils import convert, mmhash

from .base import (
    Task,
    TaskLog,
    TaskPlan,
    TaskState,
    TaskApproval,
    TaskSubtask,
    TaskIteration,
    StringOrPath,
)
from .reader import TaskFromFileSystem
from .file_parser import TaskFilesParser, TaskPlanAddRmPkgInfo
from .exceptions import TaskLoaderParserError

MTIME_NEVER = datetime.datetime.utcfromtimestamp(0)


class TaskParser:
    def __init__(self, task_path: StringOrPath, logger: logging.Logger) -> None:
        self.tf = TaskFromFileSystem(path=task_path, logger=logger)
        self.tfp = TaskFilesParser(logger=logger)
        self.logger = logger
        self.task = Task(
            id=0,
            logs=[],
            arepo=[],
            subtasks=[],
            approvals=[],
            iterations=[],
            pkg_hashes=defaultdict(PkgHash),
            state=TaskState(task_id=0, state="", task_try=0, task_iter=0),
            plan=TaskPlan(hashes={}, pkg_add={}, pkg_del={}, hash_add={}, hash_del={}),
        )

    def _parse_task_state(self) -> None:
        # parse '/task' and '/info.json' for 'TaskStates'
        # get task ID
        self.task.id = self.tf.get_int("task/id")
        if self.task.id == 0:
            raise TaskLoaderParserError("Failed to get task ID. Aborting")
        self.task.state.task_id = self.task.id
        # get task state
        if self.tf.check_file("task/state"):
            self.task.state.state = self.tf.get("task/state").strip()
            self.task.state.changed = self.tf.get_file_mtime("task/state")
            t = self.tf.get_file_mtime("info.json")
            if t and t > self.task.state.changed:  # type: ignore
                self.task.state.changed = t
        else:
            # skip tasks with uncertain state for God sake
            raise TaskLoaderParserError(
                f"Failed to get task state for {self.task.id}. Aborting"
            )

        self.task.state.runby = self.tf.get_text("task/run")
        self.task.state.task_try = self.tf.get_int("task/try")
        self.task.state.task_iter = self.tf.get_int("task/iter")
        self.task.state.message = self.tf.get_text("task/message")
        self.task.state.version = self.tf.get_text("task/version")

        t = self.tf.get("task/depends")
        self.task.state.depends = (
            [int(x) for x in t.split("\n") if len(x) > 0] if t else []
        )

        self.task.state.testonly = 1 if self.tf.check_file("task/test-only") else 0
        self.task.state.failearly = 1 if self.tf.check_file("task/fail-early") else 0

        self.task.state.shared = (
            1 if val_from_json_str(self.tf.get("info.json"), "shared") else 0
        )

        t = self.tf.get_symlink_target("build/repo/prev", name_only=True)
        self.task.state.prev = int(t) if t else 0

    def _parse_task_plan(self) -> None:
        # parse '/plan' and '/build/repo' for diff lists and hashes
        # XXX: check if task '/plan' is up to date. Workaround for bug #40728
        load_plan = False
        if self.task.state.task_try != 0 and self.task.state.task_iter != 0:
            task_tryiter_time = max(
                self.tf.get_file_mtime("task/try"),  # type: ignore
                self.tf.get_file_mtime("task/iter"),  # type: ignore
            )
            task_plan_time = self.tf.get_file_mtime("plan")
            if task_plan_time > task_tryiter_time:  # type: ignore
                load_plan = True
        # always load plan if task in 'DONE' state
        if self.task.state.state == "DONE":
            load_plan = True
        if load_plan:
            # 1 - get binary packages add and delete from plan
            pkgadd: dict[str, TaskPlanAddRmPkgInfo] = {}
            if self.tf.check_file("plan/add-src"):
                pkg_add = self.tfp.parse_add_rm_plan(
                    self.tf.get_file_path("plan/add-src"), is_add=True, is_src=True
                )
                for pkg in pkg_add:
                    pkgadd[pkg.file] = pkg
            if self.tf.check_file("plan/add-bin"):
                pkg_add = self.tfp.parse_add_rm_plan(
                    self.tf.get_file_path("plan/add-bin"), is_add=True, is_src=False
                )
                for pkg in pkg_add:
                    pkgadd[pkg.file] = pkg

            pkgdel: dict[str, TaskPlanAddRmPkgInfo] = {}
            if self.tf.check_file("plan/rm-src"):
                pkg_add = self.tfp.parse_add_rm_plan(
                    self.tf.get_file_path("plan/rm-src"), is_add=False, is_src=True
                )
                for pkg in pkg_add:
                    pkgdel[pkg.file] = pkg
            if self.tf.check_file("plan/rm-bin"):
                pkg_add = self.tfp.parse_add_rm_plan(
                    self.tf.get_file_path("plan/rm-bin"), is_add=False, is_src=False
                )
                for pkg in pkg_add:
                    pkgdel[pkg.file] = pkg

            # 2 - get packages list diffs
            empty_pkg_ = TaskPlanAddRmPkgInfo("", "", "", "", "", 0, "")
            for pkgdiff in (
                x for x in self.tf.get_file_path("plan").glob("*.list.diff")
            ):
                if pkgdiff.name == "src.list.diff":
                    p_add, p_del = self.tfp.parse_pkglist_diff(
                        pkgdiff, is_src_list=True
                    )
                else:
                    p_add, p_del = self.tfp.parse_pkglist_diff(
                        pkgdiff, is_src_list=False
                    )

                for p in p_add:
                    pp = pkgadd.get(p.file, empty_pkg_)
                    p_info = {
                        p.file: PkgInfo(
                            file=p.file,
                            name=p.name,
                            evr=p.evr,
                            srpm=p.srpm,
                            arch=p.arch,
                            comp=pp.comp,
                            path=pp.path,
                            subtask_id=pp.subtask_id,
                        )
                    }
                    if p.arch not in self.task.plan.pkg_add:
                        self.task.plan.pkg_add[p.arch] = {}
                    self.task.plan.pkg_add[p.arch].update(p_info)

                for p in p_del:
                    pp = pkgdel.get(p.file, empty_pkg_)
                    p_info = {
                        p.file: PkgInfo(
                            file=p.file,
                            name=p.name,
                            evr=p.evr,
                            srpm=p.srpm,
                            arch=p.arch,
                            comp=pp.comp,
                            path=pp.path,
                            subtask_id=pp.subtask_id,
                        )
                    }
                    if p.arch not in self.task.plan.pkg_del:
                        self.task.plan.pkg_del[p.arch] = {}
                    self.task.plan.pkg_del[p.arch].update(p_info)

            # 3 - get SHA256 hashes from '/plan/*.hash.diff'
            for hashdiff in (
                x for x in self.tf.get_file_path("plan").glob("*.hash.diff")
            ):
                h_add, h_del = self.tfp.parse_hash_diff(hashdiff)
                h_arch = hashdiff.name.split(".")[0]
                self.task.plan.hash_add[h_arch] = h_add
                self.task.plan.hash_del[h_arch] = h_del
                for k, v in h_add.items():
                    self.task.pkg_hashes[k] = PkgHash(sha256=v)

        # 2 - get MD5 and blake2b hashes from '/build/repo/%arch%/base/pkglist.task.xz'
        for pkglist in (
            x
            for x in self.tf.get_file_path("build/repo").glob("*/base/pkglist.task.xz")
        ):
            hdrs = readHeaderListFromXZFile(pkglist)
            for hdr in hdrs:
                pkg_name = convert(hdr[rpmt.RPMTAG_APTINDEXLEGACYFILENAME])
                pkg_md5 = bytes.fromhex(convert(hdr[rpmt.RPMTAG_APTINDEXLEGACYMD5]))
                pkg_blake2b = bytes.fromhex(
                    convert(hdr[rpmt.RPMTAG_APTINDEXLEGACYBLAKE2B])
                )
                if pkg_name not in self.task.pkg_hashes:
                    self.task.pkg_hashes[pkg_name] = PkgHash()
                self.task.pkg_hashes[pkg_name].blake2b = pkg_blake2b
                # XXX: workaround for duplicated noarch packages with wrong MD5 from pkglist.task.xz
                if self.task.pkg_hashes[pkg_name].md5:
                    if self.task.pkg_hashes[pkg_name].md5 != pkg_md5:
                        self.logger.debug(
                            f"Found mismatching MD5 from APT hash for {pkg_name}."
                            "Calculating MD5 from file"
                        )
                        t = [
                            x
                            for x in self.tf.get_file_path("build/repo").glob(
                                f"*/RPMS.task/{pkg_name}"
                            )
                        ]
                        if t:
                            self.task.pkg_hashes[pkg_name].md5 = md5_from_file(t[0])
                        else:
                            self.logger.error(
                                f"Failed to calculate MD5 for {pkg_name} from file"
                            )
                    else:
                        continue
                else:
                    self.task.pkg_hashes[pkg_name].md5 = pkg_md5

        # 3 - set hashes for TaskPlan* tables
        p_arch = {x for x in self.task.plan.pkg_add.keys()}
        p_arch.update({x for x in self.task.plan.pkg_del.keys()})
        p_arch.update({x for x in self.task.plan.hash_add.keys()})
        p_arch.update({x for x in self.task.plan.hash_del.keys()})
        for arch in p_arch:
            plan_hash = (
                ""
                + str(self.task.state.task_id)
                + str(self.task.state.task_try)
                + str(self.task.state.task_iter)
                + arch
            )
            self.task.plan.hashes[arch] = mmhash(plan_hash)

    def _parse_task_approvals(self) -> None:
        # parse '/acl' for 'TaskApprovals'
        # 1 - iterate through 'acl/approved'
        for subtask in (
            x.name
            for x in self.tf.get_file_path("acl/disapproved").glob("[0-7]*")
            if x.is_dir()
        ):
            subtask_dir = "/".join(("acl/approved", subtask))
            for approver in (x.name for x in self.tf.get(subtask_dir) if x.is_file()):
                t = self.tfp.parse_approval_file(
                    self.tf.get_file_path("/".join((subtask_dir, approver)))
                )
                if t:
                    self.task.approvals.append(
                        TaskApproval(
                            task_id=self.task.state.task_id,
                            subtask_id=int(subtask),
                            type="approve",
                            name=t[0],
                            date=t[1],
                            message=t[2],
                            revoked=None,
                        )
                    )
        # 2 - iterate through 'acl/dsiapproved'
        for subtask in (
            x.name
            for x in self.tf.get_file_path("acl/disapproved").glob("[0-7]*")
            if x.is_dir()
        ):
            subtask_dir = "/".join(("acl/disapproved", subtask))
            for approver in (x.name for x in self.tf.get(subtask_dir) if x.is_file()):
                t = self.tfp.parse_approval_file(
                    self.tf.get_file_path("/".join((subtask_dir, approver)))
                )
                if t:
                    self.task.approvals.append(
                        TaskApproval(
                            task_id=self.task.state.task_id,
                            subtask_id=int(subtask),
                            type="disapprove",
                            name=t[0],
                            date=t[1],
                            message=t[2],
                            revoked=None,
                        )
                    )

    def _parse_subtasks(self) -> None:
        # parse '/gears' for 'Tasks'
        for subtask in (
            x.name for x in self.tf.get_file_path("gears").glob("[0-7]*") if x.is_dir()
        ):
            subtask_dir = "/".join(("gears", subtask))
            files = set((x.name for x in self.tf.get(subtask_dir)))
            sid = self.tf.get("/".join((subtask_dir, "sid")))

            sub = TaskSubtask(
                task_id=self.task.state.task_id,
                subtask_id=int(subtask),
                task_repo=self.tf.get_text("task/repo"),
                task_owner=self.tf.get_text("task/owner"),
                task_changed=self.task.state.changed,
                subtask_changed=None,
                userid=self.tf.get_text("/".join((subtask_dir, "userid"))),
                sid=sid.split(":")[1].strip() if sid else "",
                type=sid.split(":")[0] if sid else "",
            )

            # use the latest mtime from '%subtask_dir%' and '%subtask_dir%/userid'
            userid_mtime = self.tf.get_file_mtime("/".join((subtask_dir, "userid")))
            if userid_mtime is None:
                userid_mtime = MTIME_NEVER
            sub.subtask_changed = max(userid_mtime, self.tf.get_file_mtime(subtask_dir))  # type: ignore

            if "dir" not in files and "srpm" not in files and "package" not in files:
                # deleted subtask
                sub.deleted = 1
                sub.type = "unknown"
            else:
                sub.deleted = 0
                # logic from girar-task-run check_copy_del()
                if self.tf.file_exists_and_not_empty(
                    "/".join((subtask_dir, "package"))
                ) and not self.tf.file_exists_and_not_empty(
                    "/".join((subtask_dir, "dir"))
                ):
                    if self.tf.file_exists_and_not_empty(
                        "/".join((subtask_dir, "copy_repo"))
                    ):
                        sub.type = "copy"
                        sub.pkg_from = self.tf.get_text(
                            "/".join((subtask_dir, "copy_repo"))
                        )
                    else:
                        sub.type = "delete"

                if self.tf.check_file("/".join((subtask_dir, "rebuild"))):
                    sub.type = "rebuild"
                    sub.pkg_from = self.tf.get_text("/".join((subtask_dir, "rebuild")))
                # changed in girar @ e74d8067009d
                if self.tf.check_file("/".join((subtask_dir, "rebuild_from"))):
                    sub.type = "rebuild"
                    sub.pkg_from = self.tf.get_text(
                        "/".join((subtask_dir, "rebuild_from"))
                    )
                if sub.type == "":
                    sub.type = "unknown"

                sub.dir = self.tf.get_text("/".join((subtask_dir, "dir")))
                sub.package = self.tf.get_text("/".join((subtask_dir, "package")))

                sub.tag_id = self.tf.get_text("/".join((subtask_dir, "tag_id")))
                sub.tag_name = self.tf.get_text("/".join((subtask_dir, "tag_name")))
                sub.tag_author = self.tf.get_text("/".join((subtask_dir, "tag_author")))

                sub.srpm = self.tf.get_text("/".join((subtask_dir, "srpm")))
                t = self.tf.get("/".join((subtask_dir, "nevr")))
                if t:
                    sub.srpm_name = t.split("\t")[0].strip()
                    sub.srpm_evr = t.split("\t")[1].strip()

            self.task.subtasks.append(sub)

    def _parse_iterations(self) -> None:
        # parse '/build' for 'TaskIterations'
        src_pkgs: dict[int, str] = {}
        bin_pkgs: dict[int, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )
        # 0 - get src and binary packages from plan
        t = self.tf.get_text("plan/add-src")
        if t:
            for *_, pkg_path, n in [x.split("\t") for x in t.split("\n") if len(x) > 0]:
                src_pkgs[int(n)] = pkg_path
        t = self.tf.get_text("plan/add-bin")
        if t:
            for _, _, arch, _, pkg_path, n, *_ in [
                x.split("\t") for x in t.split("\n") if len(x) > 0
            ]:
                bin_pkgs[int(n)][arch].append(pkg_path)
        # 1 - get contents from /build/%subtask_id%/%arch%
        for subtask in (
            x.name for x in self.tf.get_file_path("build").glob("[0-7]*") if x.is_dir()
        ):
            subtask_id = int(subtask)
            subtask_dir = "/".join(("build", subtask))
            # follow order of architectures from ARCHS list to prefer
            # source package from 'x86_64' and 'i586' architectures if there is no plan
            archs_fs = set((x.name for x in self.tf.get(subtask_dir) if x.is_dir()))
            archs = [x for x in ("x86_64", "i586") if x in archs_fs]
            archs += [x for x in archs_fs if x not in archs]
            for arch in archs:
                arch_dir = "/".join((subtask_dir, arch))

                ti = TaskIteration(
                    task_id=self.task.state.task_id,
                    task_changed=self.task.state.changed,
                    subtask_id=int(subtask),
                    subtask_arch=arch,
                )

                if self.tf.check_file("/".join((arch_dir, "status"))):
                    ts_ = self.tf.get_file_mtime("/".join((arch_dir, "status")))
                    ti.titer_status = self.tf.get_text(
                        "/".join((arch_dir, "status")), "failed"
                    )
                else:
                    ts_ = self.tf.get_file_mtime(arch_dir)
                    ti.titer_status = "failed"
                ti.titer_ts = ts_
                ti.task_try = self.task.state.task_try
                ti.task_iter = self.task.state.task_iter
                # read chroots
                chb_ = self.tf.get("/".join((arch_dir, "chroot_base")))
                if chb_:
                    for pkg in (
                        x.split("\t")[-1].strip()
                        for x in chb_.split("\n")
                        if len(x) > 0
                    ):
                        # FIXME: useless data due to packages stored with snowflake hash now!
                        ti.titer_chroot_base.append(mmhash(bytes.fromhex(pkg)))
                chbr_ = self.tf.get("/".join((arch_dir, "chroot_BR")))
                if chbr_:
                    for pkg in (
                        x.split("\t")[-1].strip()
                        for x in chbr_.split("\n")
                        if len(x) > 0
                    ):
                        # FIXME: useless data due to packages stored with snowflake hash now!
                        ti.titer_chroot_br.append(mmhash(bytes.fromhex(pkg)))
                # get src and bin packages
                pkgs_ = self.tf.get("/".join((arch_dir, "srpm")))
                if pkgs_ and len(pkgs_) > 0:
                    ti.titer_status = "built"
                    # skip srpm if got it from 'plan/add-src'
                    # XXX: handle particular srpm package loading somehow if plan exists
                    if subtask_id not in src_pkgs:
                        src_pkgs[subtask_id] = "/".join(
                            (arch_dir, "srpm", pkgs_[0].name)
                        )
                # set source rpm path
                ti.titer_srpm = src_pkgs.get(subtask_id, "")

                pkgs_ = self.tf.get("/".join((arch_dir, "rpms")))
                if pkgs_ and len(pkgs_) > 0:
                    ti.titer_status = "built"
                    bin_pkgs[subtask_id][arch] = []
                    for brpm in pkgs_:
                        bin_pkgs[subtask_id][arch].append(
                            "/".join((arch_dir, "rpms", brpm.name))
                        )

                if subtask_id in bin_pkgs and arch in bin_pkgs[subtask_id]:
                    ti.titer_rpms = [x for x in bin_pkgs[subtask_id][arch]]
                self.task.iterations.append(ti)
                # save build logs
                for log_file in ("log", "srpm.log"):
                    if self.tf.file_exists_and_not_empty(
                        "/".join((arch_dir, log_file))
                    ):
                        log_hash = (
                            ""
                            + str(ti.task_id)
                            + str(ti.subtask_id)
                            + str(ti.task_try)
                            + str(ti.task_iter)
                            + ti.subtask_arch
                        )
                        if log_file == "log":
                            log_hash = "build" + log_hash
                            self.task.logs.append(
                                TaskLog(
                                    type="build",
                                    path="/".join((arch_dir, log_file)),
                                    hash=mmhash(log_hash),
                                    hash_string=log_hash,
                                )
                            )
                        else:
                            log_hash = "srpm" + log_hash
                            self.task.logs.append(
                                TaskLog(
                                    type="srpm",
                                    path="/".join((arch_dir, log_file)),
                                    hash=mmhash(log_hash),
                                    hash_string=log_hash,
                                )
                            )
        # 2 - generate task iterations for subtask with 'delete' action
        build_subtasks = {x.subtask_id for x in self.task.iterations}
        for sub in self.task.subtasks:
            if sub.deleted == 0 and sub.type == "delete":
                if sub.subtask_id not in build_subtasks:
                    # create stub task iteration
                    self.task.iterations.append(
                        TaskIteration(
                            task_id=self.task.state.task_id,
                            task_changed=self.task.state.changed,
                            task_try=self.task.state.task_try,
                            task_iter=self.task.state.task_iter,
                            subtask_id=sub.subtask_id,
                            subtask_arch="x86_64",
                            titer_status="deleted",
                            titer_ts=self.tf.get_file_mtime("build"),
                        )
                    )

    def _parse_arepo_packages(self) -> None:
        # parse '/arepo' for packages
        t = self.tf.get("arepo/x86_64-i586/rpms")
        for pkg in (x.name for x in t if t and x.suffix == ".rpm"):
            self.task.arepo.append(f"arepo/x86_64-i586/rpms/{pkg}")

    def _parse_event_logs(self) -> None:
        # parse '/logs' for event logs
        for log_file in (
            x.name for x in self.tf.get_file_path("logs").glob("events.*.log")
        ):
            log_hash = (
                "events"
                + str(self.task.state.task_id)
                + log_file.split(".")[1]
                + log_file.split(".")[2]
            )
            self.task.logs.append(
                TaskLog(
                    type="events",
                    path="/".join(("logs", log_file)),
                    hash=mmhash(log_hash),
                    hash_string=log_hash,
                )
            )

    def read_task_structure(self) -> Task:
        self._parse_task_state()
        self._parse_task_plan()
        self._parse_task_approvals()
        self._parse_subtasks()
        self._parse_iterations()
        self._parse_event_logs()
        self._parse_arepo_packages()
        return self.task
