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
from copy import deepcopy
from collections import namedtuple

from altrepodb.database import DatabaseClient
from altrepodb.utils import cvt_datetime_local_to_utc

from .base import Task, TaskProcessorConfig
from .reader import TaskFromFileSystem
from .log_loader import log_load_worker_pool
from .package_loader import package_load_worker_pool
from .iteration_loader import titer_load_worker_pool


class TaskLoadHandler:
    """Handles task structure loading to DB."""

    def __init__(
        self,
        conn: DatabaseClient,
        taskfs: TaskFromFileSystem,
        logger: logging.Logger,
        task: Task,
        config: TaskProcessorConfig,
    ):
        self.tf = taskfs
        self.config = config
        self.task = task
        self.conn = conn
        self.logger = logger

    def _save_task_state(self):
        state = {
            "task_changed": self.task.state.changed,
            "task_id": self.task.state.task_id,
            "task_state": self.task.state.state,
            "task_runby": self.task.state.runby,
            "task_depends": self.task.state.depends,
            "task_try": self.task.state.task_try,
            "task_testonly": self.task.state.testonly,
            "task_failearly": self.task.state.failearly,
            "task_shared": self.task.state.shared,
            "task_message": self.task.state.message,
            "task_version": self.task.state.version,
            "task_prev": self.task.state.prev,
            "task_eventlog_hash": [
                x.hash for x in self.task.logs if x.type == "events"
            ],
        }
        self.conn.execute("INSERT INTO TaskStates_buffer (*) VALUES", [state])

    def _save_task_subtasks(self):
        subtasks = []
        for sub in self.task.subtasks:
            subtasks.append(
                {
                    "task_id": sub.task_id,
                    "subtask_id": sub.subtask_id,
                    "task_repo": sub.task_repo,
                    "task_owner": sub.task_owner,
                    "task_changed": sub.task_changed,
                    "subtask_changed": sub.subtask_changed,
                    "subtask_deleted": sub.deleted,
                    "subtask_userid": sub.userid,
                    "subtask_dir": sub.dir,
                    "subtask_package": sub.package,
                    "subtask_type": sub.type,
                    "subtask_pkg_from": sub.pkg_from,
                    "subtask_sid": sub.sid,
                    "subtask_tag_author": sub.tag_author,
                    "subtask_tag_id": sub.tag_id,
                    "subtask_tag_name": sub.tag_name,
                    "subtask_srpm": sub.srpm,
                    "subtask_srpm_name": sub.srpm_name,
                    "subtask_srpm_evr": sub.srpm_evr,
                }
            )
        if subtasks:
            self.conn.execute("INSERT INTO Tasks_buffer (*) VALUES", subtasks)

    def _save_task_iterations(self):
        if self.task.iterations:
            titer_load_worker_pool(
                self.config,
                self.conn,
                self.tf,
                self.logger,
                self.task,
                num_of_workers=0,
            )

    def _save_task_logs(self):
        if self.task.logs:
            log_load_worker_pool(
                self.config,
                self.tf,
                self.logger,
                self.task.logs,
                num_of_workers=0,
            )

    def _save_task_arepo_packages(self):
        if self.task.arepo:
            package_load_worker_pool(
                self.config,
                self.conn,
                self.tf,
                self.logger,
                self.task,
                num_of_workers=0,
                loaded_from="'/arepo'",
            )

    def _save_task_plan(self):
        # 1 - load plan package added and deleted
        payload = []
        for arch in self.task.plan.pkg_add.keys():
            for file, pkg in self.task.plan.pkg_add[arch].items():
                payload.append(
                    {
                        "tplan_hash": self.task.plan.hashes[arch],
                        "tplan_action": "add",
                        "tplan_pkg_name": pkg.name,
                        "tplan_pkg_evr": pkg.evr,
                        "tplan_bin_file": file,
                        "tplan_src_file": pkg.srpm,
                        "tplan_arch": pkg.arch,
                        "tplan_comp": pkg.comp,
                        "tplan_subtask": pkg.subtask_id,
                    }
                )
        for arch in self.task.plan.pkg_del.keys():
            for file, pkg in self.task.plan.pkg_del[arch].items():
                payload.append(
                    {
                        "tplan_hash": self.task.plan.hashes[arch],
                        "tplan_action": "delete",
                        "tplan_pkg_name": pkg.name,
                        "tplan_pkg_evr": pkg.evr,
                        "tplan_bin_file": file,
                        "tplan_src_file": pkg.srpm,
                        "tplan_arch": pkg.arch,
                        "tplan_comp": pkg.comp,
                        "tplan_subtask": pkg.subtask_id,
                    }
                )
        if payload:
            self.conn.execute("""INSERT INTO TaskPlanPackages (*) VALUES""", payload)
        # 2 - load plan package hashes add and delete
        payload = []
        for arch in self.task.plan.hash_add.keys():
            for hash in self.task.plan.hash_add[arch].values():
                payload.append(
                    {
                        "tplan_hash": self.task.plan.hashes[arch],
                        "tplan_action": "add",
                        "tplan_sha256": hash,
                    }
                )
        for arch in self.task.plan.hash_del.keys():
            for hash in self.task.plan.hash_del[arch].values():
                payload.append(
                    {
                        "tplan_hash": self.task.plan.hashes[arch],
                        "tplan_action": "delete",
                        "tplan_sha256": hash,
                    }
                )
        if payload:
            self.conn.execute("""INSERT INTO TaskPlanPkgHash (*) VALUES""", payload)

    def _save_task_approvals(self):
        # 1 - collect task approvals from DB
        Approval = namedtuple(
            "Approval",
            (
                "task_id",
                "subtask_id",
                "tapp_type",
                "tapp_revoked",
                "tapp_date",
                "tapp_name",
                "tapp_message",
            ),
        )
        res = self.conn.execute(
            """SELECT argMax(tuple(*), ts) FROM TaskApprovals
            WHERE task_id = %(task_id)s GROUP BY (subtask_id, tapp_name)""",
            {"task_id": self.task.state.task_id},
        )
        tapps_from_db = [Approval(*x[0])._asdict() for x in res]
        for tapp in tapps_from_db:
            tapp["tapp_date"] = cvt_datetime_local_to_utc(tapp["tapp_date"])

        tapps_from_fs = [
            {
                "task_id": x.task_id,
                "subtask_id": x.subtask_id,
                "tapp_type": x.type,
                "tapp_revoked": x.revoked,
                "tapp_date": x.date,
                "tapp_name": x.name,
                "tapp_message": x.message,
            }
            for x in self.task.approvals
        ]

        # 2 - collect previous approvals from DB that are not rewoked
        tapps = []
        for tapp in deepcopy(tapps_from_db):
            if tapp["tapp_revoked"] == 0:
                tapp["tapp_revoked"] = None
                tapps.append(tapp)
        # 3 - find rewoked by compare DB and actual task approvals
        tapps_revoked = []
        for tapp in tapps:
            if tapp not in tapps_from_fs:
                tapp["tapp_revoked"] = 1
                tapp["tapp_date"] = cvt_datetime_local_to_utc(datetime.datetime.now())
                tapps_revoked.append(tapp)
        # 4 - set 'tapp_rewoked' flag for new and not revoked ones
        for tapp in tapps_from_fs:
            if tapp["tapp_revoked"] is None:
                tapp["tapp_revoked"] = 0
        tapps_from_fs += tapps_revoked
        # 5 - remove task approvals that already in database
        new_task_approvals = []
        for tapp in tapps_from_fs:
            if tapp not in tapps_from_db:
                new_task_approvals.append(tapp)
        # 6 - load new approvals state to DB
        if new_task_approvals:
            self.conn.execute(
                "INSERT INTO TaskApprovals (*) VALUES", new_task_approvals
            )

    def _update_dependencies_table(self):
        sql = """
INSERT INTO Depends SELECT * FROM
(
    WITH
    unmet_file_depends AS
    (
        SELECT DISTINCT dp_name
        FROM Depends
        WHERE dp_type = 'require' AND dp_name NOT IN
        (
            SELECT dp_name
            FROM Depends
            WHERE dp_type = 'provide'
        )
            AND dp_name NOT LIKE 'rpmlib%'
    ),
    file_names_hash AS
    (
        SELECT DISTINCT
            fn_hash,
            fn_name
        FROM FileNames
        WHERE fn_name IN (SELECT * FROM unmet_file_depends)
    )
    SELECT
        pkg_hash,
        UDF.fn_name AS dp_name,
        '' AS dp_version,
        0  AS dp_flag,
        'provide' AS dp_type
    FROM Files
    INNER JOIN
    (
        SELECT * FROM file_names_hash
    ) AS UDF ON UDF.fn_hash = Files.file_hashname
)
"""
        self.logger.info("Updating Depends table for missing file riquire dependencies")
        self.conn.execute(sql)

    def _flush_buffer_tables(self):
        """Force flush bufeer tables using OPTIMIZE TABLE SQL requests."""
        buffer_tables = (
            "Files_buffer",
            "Depends_buffer",
            "Changelog_buffer",
            "Packages_buffer",
            "PackageHash_buffer",
            "TaskIterations_buffer",
            "Tasks_buffer",
            "TaskStates_buffer",
            "Specfiles_buffer",
        )
        for buffer in buffer_tables:
            self.conn.execute(f"OPTIMIZE TABLE {buffer}")

    def save(self):
        self._save_task_state()
        self._save_task_subtasks()
        self._save_task_iterations()
        self._save_task_arepo_packages()
        self._save_task_plan()
        # save task approvals from FS if enabled
        if self.config.store_approvals:
            self._save_task_approvals()
        # skip log loading for 'NEW' tasks
        if not self.config.store_logs_for_new and self.task.state.state == "NEW":
            pass
        else:
            self._save_task_logs()
        # flush buffer tables to force task consistency in DB
        if self.config.flush:
            self.logger.info("Flushing buffer tables")
            self._flush_buffer_tables()
        # update task dependencies for files
        self._update_dependencies_table()
