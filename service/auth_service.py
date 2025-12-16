from datetime import datetime
from re import I
from domain.entities import Token
import grpc
from logging import Logger, getLogger

from config import logger, settings
from decorators import grpc_error_handler
from decorators.error_handler import ErrorResponseMixin
from domain.entities import User
from domain.values import HashedPasswordSHA256
from repository.redis_repository import RedisRepository
from repository.user_repository import UserRepository
from .jwt_service import JWTService

from grpc_generated import auth_pb2_grpc, auth_pb2

from domain.exceptions import (
    InvalidTokenError,
    NotFoundError,
    InvalidArgumentError,
    AlreadyExistsError,
    UnauthorizedError,
    ForbiddenError,
    TooManyAuthenticationAttemptsError,
)


class AuthService(auth_pb2_grpc.AuthServiceServicer, ErrorResponseMixin):
    def __init__(
        self,
        cache_repository: RedisRepository,
        user_repository: UserRepository,
        jwt_service: JWTService,
        logger: Logger = None,
    ) -> None:

        self.cache_repository = cache_repository
        self.user_repository = user_repository
        self.jwt_service = jwt_service
        self.logger = logger

        if self.logger is None:
            self.logger = getLogger("AuthService")

        super().__init__()

    async def _increment_auth_attempts(self, username: str):
        """Увеличивает счетчик попыток аутентификации"""
        attempts_key = f"auth_attempt:{username}"
        try:
            # Try to increment - Redis INCR creates key with value 1 if it doesn't exist
            result = await self.cache_repository.incr(attempts_key)
            # If this was a new key (result == 1), set expiration
            if result == 1:
                await self.cache_repository.expire(attempts_key, 900)  # 15 минут
        except Exception as e:
            # Handle case where key exists but contains non-integer value (corrupted)
            # Delete and recreate with proper integer value
            self.logger.warning(
                f"Failed to increment auth attempts for {username}: {e}. Resetting counter."
            )
            await self.cache_repository.delete(attempts_key)
            await self.cache_repository.set_int(attempts_key, 1, expire=900)  # 15 минут

    @grpc_error_handler(logger=getLogger("AuthService"))
    async def authentication(self, request, context):

        cached_attempts = await self.cache_repository.get_int(
            f"auth_attempt:{request.username}"
        )

        if cached_attempts and cached_attempts >= 5:
            raise TooManyAuthenticationAttemptsError("Too many authentication attempts")

        user = await self.user_repository.get_by_username(request.username)
        if not user:
            raise NotFoundError("User not found")

        self.logger.debug(f"Найден пользак: {user}")

        if not user.authenticate(
            HashedPasswordSHA256.from_plain_password(request.password)
        ):
            await self._increment_auth_attempts(request.username)
            raise UnauthorizedError("Invalid username or password")

        if not user.is_active:
            raise ForbiddenError("User account is inactive")

        await self.cache_repository.delete(f"auth_attempt:{request.username}")

        access_token = self.jwt_service.create_access_token(user.username)
        refresh_token = self.jwt_service.create_refresh_token(user.username)

        await self.cache_repository.set(
            f"refresh_token:{user.username}",
            refresh_token,
            expire=settings.security.refresh_token_expire_minutes * 60,
        )

        await self.cache_repository.hset(
            f"user:{user.username}",
            {
                "user_id": user.user_id,
                "role": user.role.value,
                "is_active": str(user.is_active),
            },
        )
        self.logger.info(f"User authenticated: {request.username}")

        return auth_pb2.AuthResponse(
            success=True,
            message="Authentication successful",
            timestamp=datetime.now().isoformat(),
            access_token=auth_pb2.Token(
                token=access_token.token,
                token_type=auth_pb2.TokenType.BEARER,
                expires_in=settings.security.access_token_expire_minutes * 60,
            ),
            refresh_token=auth_pb2.Token(
                token=refresh_token.token,
                token_type=auth_pb2.TokenType.REFRESH,
                expires_in=settings.security.refresh_token_expire_minutes * 60,
            ),
            user=auth_pb2.User(
                username=user.username,
                role=user.role.value,  # Return string value ('USER', 'ADMIN', 'MODERATOR')
                id=user.user_id,
                is_active=user.is_active,
                created_at=user.created_at.isoformat(),
                updated_at=user.updated_at.isoformat() if user.updated_at else "",
            ),
        )

    @grpc_error_handler(logger=getLogger("AuthService"))
    async def registrate(self, request, context):
        self.logger.info(f"Registration attempt for user: {request.username}")

        if len(request.username) < 3:
            raise InvalidArgumentError("Username must be at least 3 characters long")

        if len(request.password) < 6:
            raise InvalidArgumentError("Password must be at least 6 characters long")

        existing_user = await self.user_repository.exists_with_username(
            request.username
        )

        self.logger.debug("Поиск произошел")

        if existing_user:
            raise AlreadyExistsError("User with this username already exists")

        username = request.username
        password_hash = HashedPasswordSHA256.from_plain_password(request.password)
        user = User.create(username, password_hash)

        self.logger.debug("Пользак создан")

        saved_user = await self.user_repository.save(user)
        self.logger.debug("Польказ сохранен")

        access_token = self.jwt_service.create_access_token(saved_user.username)
        refresh_token = self.jwt_service.create_refresh_token(saved_user.username)

        await self.cache_repository.set(
            f"refresh_token:{saved_user.username}",
            refresh_token,
            expire=settings.security.refresh_token_expire_minutes * 60,
        )

        await self.cache_repository.hset(
            f"user:{saved_user.username}",
            {
                "user_id": saved_user.user_id,
                "role": saved_user.role.value,
                "is_active": str(saved_user.is_active),
                "created_at": saved_user.created_at.isoformat(),
                "updated_at": saved_user.updated_at.isoformat(),
            },
        )

        self.logger.info(f"User registered: {request.username}")

        return auth_pb2.AuthResponse(
            success=True,
            message="Registration successful",
            timestamp=datetime.now().isoformat(),
            access_token=auth_pb2.Token(
                token=access_token.token,
                token_type=auth_pb2.TokenType.BEARER,
                expires_in=settings.security.access_token_expire_minutes * 60,
            ),
            refresh_token=auth_pb2.Token(
                token=refresh_token.token,
                token_type=auth_pb2.TokenType.REFRESH,
                expires_in=settings.security.refresh_token_expire_minutes * 60,
            ),
            user=auth_pb2.User(
                username=saved_user.username,
                role=saved_user.role.value,  # Return string value ('USER', 'ADMIN', 'MODERATOR')
                id=saved_user.user_id,
                is_active=saved_user.is_active,
                created_at=saved_user.created_at.isoformat(),
                updated_at=(
                    saved_user.updated_at.isoformat() if saved_user.updated_at else ""
                ),
            ),
        )

    @grpc_error_handler(logger=getLogger("AuthService"))
    async def logout(self, request, context):
        self.logger.info("Logout request")
        payload = self.jwt_service.verify_token(request)
        logger.debug(f"try to verify token, request: {request}")
        if not payload:
            logger.debug(f"token not verified, invalid payload ")
            raise InvalidTokenError("Invalid token")

        logger.debug(f"token verified")
        logger.debug(f"payload: {payload}")
        logger.debug(f"request: {request}")
        logger.debug(f"try to verify token")

        return auth_pb2.SuccessResponse(
            success=True,
            message="Logout successful",
            timestamp=datetime.now().isoformat(),
        )

    async def refresh_token(self, request, context):
        self.logger.info("Refresh token request")

        payload = self.jwt_service.verify_token(request)
        if not payload:
            raise InvalidTokenError("Invalid token payload")

        username = payload.get("sub")
        if not username:
            raise InvalidTokenError("Invalid token payload")

        if payload.get("type") != "refresh":
            raise InvalidTokenError("Not a refresh token")

        self.logger.debug(f"key: refresh_token:{username}")

        cached_refresh_token = await self.cache_repository.get(
            f"refresh_token:{username}"
        )

        if cached_refresh_token is None:
            raise InvalidTokenError("Refresh token not found or expired")
        self.logger.debug(f"cahced_refresh_token: {cached_refresh_token}")

        if (
            isinstance(cached_refresh_token, Token)
            and cached_refresh_token.token != request.token
        ):
            raise InvalidTokenError("Refresh token not found or expired")

        elif (
            isinstance(cached_refresh_token, str)
            and cached_refresh_token != request.token
        ):
            raise InvalidTokenError("Refresh token not found or expired")

        new_access_token = self.jwt_service.create_access_token(username)
        new_refresh_token = self.jwt_service.create_refresh_token(username)

        await self.cache_repository.set(
            f"refresh_token:{username}",
            new_refresh_token.token,
            expire=settings.security.refresh_token_expire_minutes * 60,
        )

        self.logger.info(f"Tokens refreshed for user: {username}")

        return auth_pb2.AuthResponse(
            success=True,
            message="Tokens refreshed successfully",
            timestamp=datetime.now().isoformat(),
            access_token=auth_pb2.Token(
                token=new_access_token.token,
                token_type=auth_pb2.TokenType.BEARER,
                expires_in=settings.security.access_token_expire_minutes * 60,
            ),
            refresh_token=auth_pb2.Token(
                token=new_refresh_token.token,
                token_type=auth_pb2.TokenType.REFRESH,
                expires_in=settings.security.refresh_token_expire_minutes * 60,
            ),
        )

    @grpc_error_handler(logger=getLogger("AuthService"))
    async def get_user(self, request, context):
        self.logger.info("Get user request")

        payload = self.jwt_service.verify_token(request)
        if not payload:
            raise InvalidTokenError("Invalid token payload")

        username = payload.get("sub")
        if not username:
            raise InvalidTokenError("Invalid token payload")

        cached_user = await self.cache_repository.hgetall(f"user:{username}")

        if cached_user:
            return auth_pb2.User(
                username=username,
                role=cached_user.get("role", "USER"),  # Return string value directly
                id=cached_user.get("user_id", ""),
                is_active=cached_user.get("is_active", "True") == "True",
                created_at=cached_user.get("created_at", ""),  # Из кэша нет created_at
                updated_at=cached_user.get("updated_at", ""),
            )

        user = await self.user_repository.get_by_username(username)
        if not user:
            raise NotFoundError("User not found")

        return auth_pb2.User(
            username=user.username,
            role=user.role.value,  # Return string value ('USER', 'ADMIN', 'MODERATOR')
            id=user.user_id,
            is_active=user.is_active,
            created_at=user.created_at.isoformat(),
            updated_at=user.updated_at.isoformat() if user.updated_at else "",
        )

    @grpc_error_handler(logger=getLogger("AuthService"))
    async def verify(self, request, context):
        self.logger.info("Token verification request")

        is_blacklisted = await self.cache_repository.exists(
            f"blacklist:{request.token}"
        )
        if is_blacklisted:
            raise InvalidTokenError("Token is blacklisted")

        payload = self.jwt_service.verify_token(request)
        if not payload:
            raise InvalidTokenError("Invalid token payload")

        username = payload.get("sub")
        if not username:
            raise InvalidTokenError("Invalid token payload")

        user_exists = await self.user_repository.exists_with_username(username)
        if not user_exists:
            raise InvalidTokenError("invalid token payload")

        return auth_pb2.SuccessResponse(
            success=True,
            message="Token is valid",
            timestamp=datetime.now().isoformat(),
        )

    async def change_password(self, request, context):
        self.logger.info("Change password request")

        payload = self.jwt_service.verify_token(request.token)
        if not payload:
            raise InvalidTokenError("Invalid token payload")

        username = payload.get("sub")
        if not username:
            raise InvalidTokenError("Invalid token payload")

        user = await self.user_repository.get_by_username(username)
        if not user:
            raise InvalidTokenError("invalid token payload")

        hashed_password = HashedPasswordSHA256.from_plain_password(
            request.current_password
        )
        if not user.authenticate(hashed_password):
            raise InvalidTokenError("invalid token payload")

        if len(request.new_password) < 6:
            raise InvalidArgumentError(
                "New password must be at least 6 characters long"
            )

        new_password_hash = HashedPasswordSHA256.from_plain_password(
            request.new_password
        )
        user.change_password(new_password_hash)
        self.logger.debug(f"new user: {user}")
        await self.user_repository.save(user)

        await self.cache_repository.delete(f"refresh_token:{username}")

        self.logger.info(f"Password changed for user: {username}")

        return auth_pb2.SuccessResponse(
            success=True,
            message="Password changed successfully",
            timestamp=datetime.now().isoformat(),
        )
