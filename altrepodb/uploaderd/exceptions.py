class ServiceError(Exception):
    pass


class ServiceUnexpectedMessage(ServiceError):
    def __init__(self, got: str, expected: str):
        super().__init__(f"Unexpected message '{got}', expected '{expected}'")


class ServiceFailMessage(ServiceError):
    def __init__(self):
        super().__init__("Service Failed")


class ServiceLoadConfigError(ServiceError):
    def __init__(self, message: str = ""):
        super().__init__(f"Service Load Config Error: {message}")


class ServiceStartError(ServiceError):
    pass
