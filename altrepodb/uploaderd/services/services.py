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

from ..service import ServiceBase

from .task_service import TaskLoaderService
from .acl_service import AclLoaderService
from .bugzilla_service import BugzillaLoaderService
from .beehive_service import BeehiveLoaderService
from .repocop_service import RepocopLoaderService
from .watch_service import WatchLoaderService
from .repo_service import RepoLoaderService


SERVICES: dict[str, type[ServiceBase]] = {
    "task_loader": TaskLoaderService,
    "acl_loader": AclLoaderService,
    "bug_loader": BugzillaLoaderService,
    "beehive_loader": BeehiveLoaderService,
    "repocop_loader": RepocopLoaderService,
    "watch_loader": WatchLoaderService,
    "repo_service": RepoLoaderService,
}
