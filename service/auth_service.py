from datetime import datetime
from logging import Logger, getLogger
from grpc import aio
import asyncio

from config import settings
from decorators import grpc_error_handler
from decorators.error_handler import ErrorResponseMixin
from domain.entities import User
from domain.values import HashedPasswordSHA256
from repository.redis_repository import RedisRepository
from repository.user_repository import UserRepository
from .jwt_service import JWTService

from domain.enums import TokenType
from grpc_generated import auth_pb2_grpc, auth_pb2


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
        current_attempts = await self.cache_repository.get(attempts_key)
        if current_attempts:
            await self.cache_repository.incr(attempts_key)
        else:
            await self.cache_repository.set(attempts_key, "1", expire=900)  # 15 минут

    @grpc_error_handler(logger=getLogger("AuthService"))
    async def authentication(self, request, context):

        cached_attempts = await self.cache_repository.get(
            f"auth_attempt:{request.username}"
        )

        if cached_attempts and int(cached_attempts) >= 5:
            raise ValueError("Too many authentication attempts")

        user = await self.user_repository.get_by_username(request.username)
        self.logger.debug(f"Найден пользак: {user}")
        if not user:
            await self._increment_auth_attempts(request.username)
            raise ValueError("Invalid username or password")

        if not user.authenticate(
            HashedPasswordSHA256.from_plain_password(request.password)
        ):
            await self._increment_auth_attempts(request.username)
            raise ValueError("Invalid username or password")

        if not user.is_active:
            raise ValueError("User account is inactive")

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
                role=auth_pb2.UserRole.Value(user.role.value),
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
            raise ValueError("Username must be at least 3 characters long")

        if len(request.password) < 6:
            raise ValueError("Password must be at least 6 characters long")

        existing_user = await self.user_repository.exists_with_username(
            request.username
        )

        self.logger.debug("Поиск произошел")

        if existing_user:
            raise ValueError("Username already exists")

        username = request.username
        password_hash = HashedPasswordSHA256.from_plain_password(request.password)
        user = User.create(username, password_hash)

        self.logger.debug("Юзер создан")

        saved_user = await self.user_repository.save(user)
        self.logger.debug("Юзер сохранен")

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
                role=auth_pb2.UserRole.Value(saved_user.role.value),
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
        if not payload:
            raise ValueError("Invalid token")

        username = payload.get("sub")
        if not username:
            raise ValueError("Invalid token payload")

        await self.cache_repository.delete(f"refresh_token:{username}")

        await self.cache_repository.set(
            f"blacklist:{request.token}",
            "1",
            expire=settings.security.access_token_expire_minutes * 60,
        )

        self.logger.info(f"User logged out: {username}")

        return auth_pb2.SuccessResponse(
            success=True,
            message="Logout successful",
            timestamp=datetime.now().isoformat(),
        )

    @grpc_error_handler(logger=getLogger("AuthService"))
    async def refresh_token(self, request, context):
        self.logger.info("Refresh token request")

        if request.token_type != auth_pb2.TokenType.REFRESH:
            raise ValueError("Not a refresh token")

        payload = self.jwt_service.verify_token(request)
        if not payload:
            raise ValueError("Invalid refresh token")

        username = payload.get("sub")
        if not username:
            raise ValueError("Invalid token payload")

        if payload.get("type") != "refresh":
            raise ValueError("Not a refresh token")

        self.logger.debug(f"key: refresh_token:{username}")

        cached_refresh_token = await self.cache_repository.get(
            f"refresh_token:{username}"
        )

        self.logger.debug(f"cahced_refresh_token: {cached_refresh_token}")

        if cached_refresh_token.token != request.token:
            raise ValueError("Refresh token not found or expired")

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
            raise ValueError("Invalid token")

        username = payload.get("sub")
        if not username:
            raise ValueError("Invalid token")

        cached_user = await self.cache_repository.hgetall(f"user:{username}")

        if cached_user:
            return auth_pb2.User(
                username=username,
                role=auth_pb2.UserRole.Value(cached_user.get("role", "USER")),
                id=cached_user.get("user_id", ""),
                is_active=cached_user.get("is_active", "True") == "True",
                created_at=cached_user.get("created_at", ""),  # Из кэша нет created_at
                updated_at=cached_user.get("updated_at", ""),
            )

        user = await self.user_repository.get_by_username(username)
        if not user:
            return auth_pb2.User()

        return auth_pb2.User(
            username=user.username,
            role=auth_pb2.UserRole.Value(user.role.value),
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
            raise ValueError("Token is blacklisted")

        payload = self.jwt_service.verify_token(request)
        if not payload:
            raise ValueError("Invalid token")

        username = payload.get("sub")
        if not username:
            raise ValueError("Invalid token payload")

        user_exists = await self.user_repository.exists_with_username(username)
        if not user_exists:
            raise ValueError("User not found")

        return auth_pb2.SuccessResponse(
            success=True,
            message="Token is valid",
            timestamp=datetime.now().isoformat(),
        )

    @grpc_error_handler(logger=getLogger("AuthService"))
    async def change_password(self, request, context):
        self.logger.info("Change password request")

        payload = self.jwt_service.verify_token(request.token)
        if not payload:
            raise ValueError("Invalid token")

        username = payload.get("sub")
        if not username:
            raise ValueError("Invalid token payload")

        user = await self.user_repository.get_by_username(username)
        if not user:
            raise ValueError("User not found")

        hashed_password = HashedPasswordSHA256.from_plain_password(
            request.current_password
        )
        if not user.authenticate(hashed_password):
            raise ValueError("Current password is incorrect")

        if len(request.new_password) < 6:
            raise ValueError("New password must be at least 6 characters long")

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


async def serve():
    host = settings.grpc.host
    port = settings.grpc.port

    server = aio.server()

    from container import container

    container.init_resources()
    auth_service = container.services.auth_service()

    async def create_tables():
        """Создание таблиц в базе данных"""
        try:
            # Получаем сессию из провайдера
            async with container.database.database_session() as session:
                # Создаем таблицы через миграции или прямое создание
                from database import Base

                async with container.database.database_engine().begin() as conn:
                    await conn.run_sync(Base.metadata.create_all)
        except Exception as e:
            raise

    await create_tables()

    auth_pb2_grpc.add_AuthServiceServicer_to_server(auth_service, server)

    server.add_insecure_port(f"{host}:{port}")

    await server.start()

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        await server.stop(0)
        container.shutdown_resources()


if __name__ == "__main__":
    asyncio.run(serve())
