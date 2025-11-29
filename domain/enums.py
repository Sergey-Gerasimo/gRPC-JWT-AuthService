from enum import Enum


class UserRole(str, Enum):
    USER = "USER"
    ADMIN = "ADMIN"
    MODERATOR = "MODERATOR"


class TokenType(str, Enum):
    BEARER = "BEARER"
    REFRESH = "REFRESH"
