from datetime import datetime, timezone, timedelta
from logging import Logger
from typing import Any, Optional, Union
from jose import JWTError, jwt

from domain.entities import Token
from domain.enums import TokenType


class JWTService:
    def __init__(
        self,
        access_token_expire_minutes: int,
        refresh_token_expire_minutes: int,
        secret_key: str,
        algorithm: str,
        logger: Logger = None,
    ):
        self.expire = access_token_expire_minutes
        self.refresh_expire = refresh_token_expire_minutes
        self.algorithm = algorithm
        self.secret_key = secret_key
        self._logger = logger

    def _create_token(
        self, subject: str, expires_in_minutes: int, extra_claims: dict | None = None
    ) -> str:
        now = datetime.now(tz=timezone.utc)
        expiration_time = now + timedelta(minutes=expires_in_minutes)
        payload = {"exp": expiration_time, "sub": subject}
        if extra_claims:
            payload.update(extra_claims)
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_access_token(
        self, subject: str, expires_delta: int = None, extra_claims: dict | None = None
    ) -> Token:
        if expires_delta is None:
            expires_delta = self.expire

        if extra_claims is not None:
            extra_claims["type"] = "access"

        else:
            extra_claims = {"type": "access"}

        string_token = self._create_token(subject, expires_delta, extra_claims)

        token = Token.create(
            token_string=string_token,
            token_type=TokenType.BEARER,
            expires_in=expires_delta,
        )

        return token

    def create_refresh_token(
        self,
        subject: Union[str, Any],
        expires_delta: int = None,
        extra_claims: dict | None = None,
    ) -> Token:
        if expires_delta is None:
            expires_delta = self.expire

        if extra_claims is not None:
            extra_claims["type"] = "access"
        else:
            extra_claims = {"type": "refresh"}

        string_token = self._create_token(subject, expires_delta, extra_claims)

        token = Token.create(
            token_string=string_token,
            token_type=TokenType.REFRESH,
            expires_in=expires_delta,
        )
        return token

    def _warn_msg(self, msg: str) -> None:
        if self._logger is not None:
            self._logger.warning(msg)

    def verify_token(self, token: Token) -> Union[dict, None]:
        try:
            payload = jwt.decode(
                token.token, self.secret_key, algorithms=[self.algorithm]
            )
            return payload
        except JWTError as e:
            self._warn_msg(f"JWT verification failed: {e}")
            return None

    def decode(self, token: Token) -> tuple[bool, Optional[dict]]:
        try:
            payload = jwt.decode(
                token.token, self.secret_key, algorithms=[self.algorithm]
            )
            return True, payload

        except JWTError as e:
            self._warn_msg(f"JWT decoding failed: {e}")
            return False, None
