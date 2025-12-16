class NotFoundError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class InvalidArgumentError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class AlreadyExistsError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class UnauthorizedError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class ForbiddenError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class TooManyAuthenticationAttemptsError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class InvalidTokenError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
