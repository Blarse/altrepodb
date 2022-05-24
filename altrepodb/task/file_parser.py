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

import re
import logging
import datetime
from pathlib import Path
from typing import Union, Iterator
from collections import namedtuple

from altrepodb.utils import set_datetime_timezone_to_utc
from .base import StringOrPath

# namedtuples
LogLine = namedtuple("LogLine", ["line", "ts", "message"])
TaskPlanDiffPkgInfo = namedtuple(
    "TaskPlanDiffPkgInfo", ["name", "evr", "file", "srpm", "arch"]
)
TaskPlanAddRmPkgInfo = namedtuple(
    "TaskPlanAddRmPkgInfo",
    ["name", "evr", "arch", "file", "path", "subtask_id", "comp"],
)


class TaskFilesParser:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def parse_approval_file(
        self, path: StringOrPath
    ) -> Union[None, tuple[str, datetime.datetime, str]]:
        try:
            content = Path(path).read_text()
        except (FileNotFoundError, IsADirectoryError):
            return None
        n = d = m = None
        if content:
            try:
                d, *m = [x for x in content.split("\n") if len(x) > 0]
                d, n = [x.strip() for x in d.split("::") if len(x) > 0]
                n = n.split(" ")[-1]
                d = datetime.datetime.strptime(d, "%Y-%b-%d %H:%M:%S")
                d = set_datetime_timezone_to_utc(d)
                m = "\n".join((x for x in m))
                return (n, d, m)
            except Exception as e:
                self.logger.error(
                    f"File parsing failed with error {e} for '{path}' contains '{content}'"
                )
        return None

    @staticmethod
    def parse_pkglist_diff(
        diff_file: StringOrPath, is_src_list: bool
    ) -> tuple[list[TaskPlanDiffPkgInfo], list[TaskPlanDiffPkgInfo]]:
        """Parse package list diff file. Returns tuple of added and deleted packages lists."""

        diff_pattern = re.compile(r"^[+-]+[a-zA-Z0-9]+\S+")  # type: ignore
        p_added: list[TaskPlanDiffPkgInfo] = []
        p_deleted: list[TaskPlanDiffPkgInfo] = []
        try:
            contents = Path(diff_file).read_text()
            contents = (x for x in contents.split("\n") if len(x) > 0)
        except FileNotFoundError:
            return [], []
        for line in contents:
            p = diff_pattern.findall(line)
            if p:
                sign = p[0][0]
                if is_src_list:
                    pkg_name = p[0][1:].strip()
                    pkg_evr, pkg_file = [
                        x.strip()
                        for x in diff_pattern.split(line)[-1].split("\t")
                        if len(x) > 0
                    ]
                    pkg_src = pkg_file
                    pkg_arch = "src"
                else:
                    pkg_name = p[0][1:].strip()
                    pkg_evr, pkg_arch, pkg_file, pkg_src = [
                        x.strip()
                        for x in diff_pattern.split(line)[-1].split("\t")
                        if len(x) > 0
                    ]
                if sign == "+":
                    p_added.append(
                        TaskPlanDiffPkgInfo(
                            pkg_name, pkg_evr, pkg_file, pkg_src, pkg_arch
                        )
                    )
                else:
                    p_deleted.append(
                        TaskPlanDiffPkgInfo(
                            pkg_name, pkg_evr, pkg_file, pkg_src, pkg_arch
                        )
                    )
        return p_added, p_deleted

    @staticmethod
    def parse_add_rm_plan(
        fname: StringOrPath, is_add: bool, is_src: bool
    ) -> list[TaskPlanAddRmPkgInfo]:
        """Parse task plan package add/delete files. Return list of packages."""

        res: list[TaskPlanAddRmPkgInfo] = []
        try:
            contents = Path(fname).read_text()
            contents = (x for x in contents.split("\n") if len(x) > 0)
        except FileNotFoundError:
            return res
        for line in contents:
            s = line.split("\t")
            if is_add:
                # parse 'add-src' or 'add-bin' file
                if is_src:  # parse 'add-src' file
                    res.append(
                        TaskPlanAddRmPkgInfo(*s[0:2], "src", *s[2:4], int(s[4]), "")  # type: ignore
                    )
                else:  # parse 'add-bin' file
                    if len(s) >= 7:
                        res.append(TaskPlanAddRmPkgInfo(*s[0:5], int(s[5]), s[6]))  # type: ignore
                    else:
                        res.append(TaskPlanAddRmPkgInfo(*s[0:5], int(s[5]), ""))  # type: ignore
            else:
                # parse 'rm-src' or 'rm-bin' file
                if is_src:  # parse 'rm-src' file
                    res.append(
                        TaskPlanAddRmPkgInfo(*s[0:2], "src", s[2], "", 0, "")  # type: ignore
                    )
                else:  # parse 'rm-bin' file
                    if len(s) >= 5:
                        res.append(TaskPlanAddRmPkgInfo(*s[0:4], "", 0, s[4]))  # type: ignore
                    else:
                        res.append(TaskPlanAddRmPkgInfo(*s, "", 0, ""))  # type: ignore
        return res

    @staticmethod
    def parse_hash_diff(hash_file: StringOrPath) -> tuple[dict, dict]:
        """Parse hash diff file. Returns added and deleted hashes as dictionaries."""

        hash_pattern = re.compile(r"^[+-]+[0-9a-f]{64}\s+")  # type: ignore
        h_added: dict[str, bytes] = {}
        h_deleted: dict[str, bytes] = {}
        try:
            contents = Path(hash_file).read_text()
            contents = (x for x in contents.split("\n") if len(x) > 0)
        except FileNotFoundError:
            return {}, {}
        for line in contents:
            h = hash_pattern.findall(line)
            if h:
                sign = h[0][0]
                sha256 = h[0][1:].strip()
                pkg_name = hash_pattern.split(line)[-1].strip()
                if sign == "+":
                    h_added[pkg_name] = bytes.fromhex(sha256)
                else:
                    h_deleted[pkg_name] = bytes.fromhex(sha256)
        return h_added, h_deleted

    def log_parser(
        self,
        log_file: StringOrPath,
        log_type: str,
        log_start_time: datetime.datetime,
    ) -> Iterator[LogLine]:
        """Task logs parser generator

        Args:
            log_file (str): log file name
            log_type (str): log type ('events'|'build'|'srpm')
            log_start_time (datetime): log start time for logs with
            partial or none timestamps included

        Returns:
            generator(tuple(int, datetime, str)): return parsed log as
            generator of tuples of line number, timestamp and message
        """
        # matches with '2020-May-15 10:30:00 '
        events_pattern = re.compile(r"^\d{4}-[A-Z][a-z]{2}-\d{2}\s\d{2}:\d{2}:\d{2}")  # type: ignore
        # matches with '<13>Sep 13 17:53:14 '
        srpm_pattern = re.compile(r"^<\d+>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}")  # type: ignore
        # matches with '[00:03:15] '
        build_pattern = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]")  # type: ignore

        if not Path(log_file).is_file():
            self.logger.error(f"File '{log_file}' not found")
            return tuple()

        if log_type == "srpm" and not isinstance(log_start_time, datetime.datetime):
            self.logger.error(
                f"Valid 'log_start_time' value is required to parse 'srpm.log'"
                f" type file {log_file}. Log file parsing aborted."
            )
            return tuple()

        first_line = True
        line_cnt = 0

        # srpm build log parser
        def srpm_log(line: str) -> LogLine:
            nonlocal line_cnt
            nonlocal first_line

            line_cnt += 1
            dt = srpm_pattern.findall(line)
            msg = srpm_pattern.split(line)[-1].strip()

            if dt:
                dt = dt[0]
                srpm_log.last_dt = dt
                first_line = False
                # XXX: workaround for 'Feb 29' (https://bugs.python.org/issue26460)
                ts_str = f"{str(log_start_time.year)} " + " ".join(
                    [x for x in dt[4:].split(" ") if len(x) > 0]
                )
                ts = datetime.datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
            else:
                if first_line:
                    self.logger.debug(
                        f"File '{log_file}' first line doesn't contain valid datetime."
                        f" Using 'log_start_time' as timestamp."
                    )
                    ts = log_start_time
                else:
                    ts_str = f"{str(log_start_time.year)} " + " ".join(
                        [x for x in srpm_log.last_dt[4:].split(" ") if len(x) > 0]  # type: ignore
                    )
                    ts = datetime.datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")

            return LogLine(line_cnt, ts, msg)

        # static-like function variable
        srpm_log.last_dt = None

        # build log parser
        def build_log(line: str) -> LogLine:
            nonlocal line_cnt
            nonlocal first_line

            line_cnt += 1
            ts = build_pattern.findall(line)
            msg = build_pattern.split(line)[-1].strip()
            if ts:
                ts = ts[0][1:-1].split(":")
                ts = log_start_time + datetime.timedelta(
                    hours=int(ts[0]), minutes=int(ts[1]), seconds=int(ts[2])
                )
            else:
                ts = log_start_time

            return LogLine(line=line_cnt, ts=ts, message=msg)

        # events log parser
        def events_log(line: str) -> Union[LogLine, None]:
            nonlocal line_cnt
            nonlocal first_line

            line_cnt += 1
            dt = events_pattern.findall(line)
            msg = events_pattern.split(line)[-1].split(" :: ")[-1].strip()

            if first_line:
                if not dt:
                    self.logger.error(
                        f"File '{log_file}' first line doesn't contain"
                        f" valid datetime. Log file parsing aborted."
                    )
                    return None
                dt = dt[0]
                events_log.last_dt = dt
                first_line = False
                ts = datetime.datetime.strptime(dt, "%Y-%b-%d %H:%M:%S")
            else:
                if dt:
                    dt = dt[0]
                    events_log.last_dt = dt
                    ts = datetime.datetime.strptime(dt, "%Y-%b-%d %H:%M:%S")
                else:
                    ts = datetime.datetime.strptime(
                        events_log.last_dt, "%Y-%b-%d %H:%M:%S"
                    )

            return LogLine(line=line_cnt, ts=ts, message=msg)

        # static-like function variable
        events_log.last_dt = None

        type_to_parser = {"srpm": srpm_log, "build": build_log, "events": events_log}

        parser = type_to_parser.get(log_type, None)
        if parser is None:
            self.logger.error(
                f"Unknown log format specifier '{log_type}'."
                " Log file parsing aborted."
            )
            return tuple()

        with Path(log_file).open("r", encoding="utf-8", errors="backslashreplace") as f:
            for line in f:
                if len(line) > 0:  # skip an empty lines
                    p = parser(line)
                    if not p:
                        raise StopIteration
                    else:
                        yield p
