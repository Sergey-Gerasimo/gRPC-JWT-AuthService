from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, ConfigDict

from domain.enums import TokenType
from config import settings


class Token(BaseModel):
    model_config = ConfigDict(
        frozen=True,  # Токены иммутабельны
        arbitrary_types_allowed=True,
    )

    token: str
    token_type: TokenType
    expires_in: int

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
