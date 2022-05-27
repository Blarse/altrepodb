from ..service import ServiceBase

from .test_service import TestService
from .task_service import TaskLoaderService
from .bugzilla_service import BugzillaLoaderService


SERVICES: dict[str, type[ServiceBase]] = {
    "task_loader": TaskLoaderService,
    "bug_loader": BugzillaLoaderService,
    "test_service": TestService,
}
