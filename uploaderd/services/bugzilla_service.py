import logging

from ..service import ServiceBase

NAME = "altrepodb.bugzilla_loader"

logger = logging.getLogger(NAME)


class BugzillaLoaderService(ServiceBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logger
        raise NotImplementedError

    def load_config(self):
        super().load_config()
