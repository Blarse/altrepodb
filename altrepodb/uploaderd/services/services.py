from ..service import ServiceBase

from .task_service import TaskLoaderService
from .bugzilla_service import BugzillaLoaderService


SERVICES: dict[str, type[ServiceBase]] = {
    "task_loader": TaskLoaderService,
    "bug_loader": BugzillaLoaderService,
}
