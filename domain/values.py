import hashlib
import re
from pydantic import BaseModel, field_validator
from typing import TypeVar, Any, Generic
from abc import ABC, abstractmethod

VT = TypeVar("VT", bound=Any)


class BaseValueObject(BaseModel, ABC, Generic[VT]):
    value: VT

    @field_validator("value")
    @abstractmethod
    def validate_value(cls, v: VT) -> VT:
        """Валидация значения value object"""
        pass

    @abstractmethod
    def as_generic_type(self) -> Any:
        """Преобразование в базовый тип"""
        pass

    def __str__(self) -> str:
        return str(self.value)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, BaseValueObject):
            return self.value == other.value
        return self.value == other

    def __hash__(self) -> int:
        return hash(self.value)

    class Config:
        frozen = True
        arbitrary_types_allowed = True


class HashedPasswordSHA256(BaseValueObject[str]):
    value: str

    @field_validator("value")
    def validate_value(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Hashed password must be a string")

        if len(v) == 0:
            raise ValueError("Hashed password cannot be empty")

        # Проверка формата SHA-256
        # SHA-256 хэш должен быть 64 символа в hex формате
        sha256_pattern = r"^[a-fA-F0-9]{64}$"

        if not re.match(sha256_pattern, v):
            raise ValueError(
                "Invalid SHA-256 hash format. "
                "Must be exactly 64 hexadecimal characters"
            )

        return v

    def as_generic_type(self) -> str:
        return self.value

    def verify(self, plain_password: str) -> bool:
        hashed_input = hashlib.sha256(plain_password.encode()).hexdigest()
        return hashed_input == self.value

    @classmethod
    def from_plain_password(cls, plain_password: str) -> "HashedPasswordSHA256":
        if not plain_password:
            raise ValueError("Password cannot be empty")
        if len(plain_password) < 4:
            raise ValueError("Password must be at least 4 characters long")

        hashed = hashlib.sha256(plain_password.encode()).hexdigest()
        return cls(value=hashed)

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"HashedPasswordSHA256('{self.value}')"
