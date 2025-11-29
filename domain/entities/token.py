from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel

from domain.enums import TokenType
from config import settings


class Token(BaseModel):
    token: str
    token_type: TokenType
    expires_in: int

    class Config:
        frozen = True  # Токены иммутабельны
        arbitrary_types_allowed = True

    @classmethod
    def create(
        cls,
        token_string: str,
        token_type: TokenType,
        expires_in: int,
    ) -> "Token":
        return cls(
            token=token_string,
            token_type=token_type,
            expires_in=expires_in,
        )
