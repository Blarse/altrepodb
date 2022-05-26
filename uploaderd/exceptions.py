class ServiceError(Exception):
    pass


class ServiceUnexpectedMessage(ServiceError):
    def __init__(self, got: str, expected: str):
        super().__init__(f"Unexpected message '{got}', expected '{expected}'")


class ServiceFailMessage(ServiceError):
    def __init__(self):
        super().__init__("Service Failed")


class ServiceIpcSendError(ServiceError):
    def __init__(self, message: str = ""):
        super().__init__(f"Service Ipc Send Error: {message}")


class ServiceIpcRecvError(ServiceError):
    def __init__(self, message: str = ""):
        super().__init__(f"Service Ipc Receive Error: {message}")


class ServiceIpcTimeout(ServiceError):
    def __init__(self, message: str = ""):
        super().__init__(f"Service Ipc Timeout: {message}")


class ServiceLoadConfigError(ServiceError):
    def __init__(self, message: str = ""):
        super().__init__(f"Service Load Config Error: {message}")


class ServiceStartError(ServiceError):
    pass
