from typing import Callable, Any, List, Optional, Tuple
import grpc
from grpc import aio
from config import logger
from domain.exceptions import UnauthorizedError, ForbiddenError, InvalidTokenError
from domain.enums import TokenType, UserRole
from service.jwt_service import JWTService
from domain.entities import Token
from repository.user_repository import UserRepository
from repository.redis_repository import RedisRepository


_AUTH_HEADER_KEY = "authorization"
_AUTH_HEADER_VALUE = "Bearer"

# Методы, которые не требуют авторизации
PUBLIC_METHODS = {
    "/grpc.AuthService/authentication",
    "/grpc.AuthService/registrate",
    "/grpc.AuthService/refresh_token",
    "/grpc.AuthService/verify",
}

# Методы, требующие роль ADMIN
ADMIN_METHODS = {
    "/grpc.UserService/create_user",
    "/grpc.UserService/delete_user",
    "/grpc.UserService/update_user",
}

# Методы, требующие роль ADMIN или MODERATOR
ADMIN_OR_MODERATOR_METHODS = {
    "/grpc.UserService/get_user",
    "/grpc.UserService/get_user_by_username",
    "/grpc.UserService/list_users",
}


class AuthInterceptor(aio.ServerInterceptor):
    """Interceptor для проверки авторизации (упрощенная версия по образцу gRPC примера)"""

    def __init__(
        self,
        jwt_service: JWTService,
        user_repository: UserRepository,
        cache_repository: RedisRepository,
    ):
        self.jwt_service = jwt_service
        self.user_repository = user_repository
        self.cache_repository = cache_repository

    def _create_abort_handler(self, error_message: str = "Authorization required"):
        """Создает handler для отклонения запросов без авторизации"""

        def abort_handler(request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, error_message)

        # Создаем правильный handler объект для асинхронного gRPC
        return grpc.unary_unary_rpc_method_handler(abort_handler)

    def _get_token_from_metadata(self, invocation_metadata: List[Any]) -> Optional[str]:
        for item in invocation_metadata:
            if hasattr(item, "key") and hasattr(item, "value"):
                key = item.key.lower()
                value = item.value
                if key == _AUTH_HEADER_KEY.lower():
                    return value
        return None

    async def intercept_service(
        self,
        continuation: Callable,
        handler_call_details: Any,
    ) -> Any:
        """Перехватывает вызовы методов и проверяет авторизацию"""

        # Получаем вызываемый метод
        method_name = handler_call_details.method
        logger.debug(f"Method name: {method_name}")

        # Публичные методы - пропускаем без проверки
        if method_name in PUBLIC_METHODS:
            logger.debug(f"Public method: {method_name}, skipping auth check")
            return await continuation(handler_call_details)

        # Извлекаем метаданные из invocation_metadata
        # invocation_metadata содержит объекты _Metadatum с атрибутами key и value
        token_string = None
        invocation_metadata = handler_call_details.invocation_metadata
        logger.debug(f"Invocation metadata: {invocation_metadata}")

        # Ищем токен в метаданных
        token_string = self._get_token_from_metadata(invocation_metadata)

        # Если токен не найден, отклоняем запрос
        if not token_string:
            logger.debug(f"Authorization token not found for method: {method_name}")
            return self._create_abort_handler("Authorization token required")

        # Убираем префикс "Bearer " если есть
        if token_string.startswith("Bearer "):
            token_string = token_string[7:]

        # Валидируем токен
        valid, role = await self._validate_token(token_string)
        logger.debug(f"Token validation result - Valid: {valid}, Role: {role}")

        if not valid:
            logger.debug(f"Token validation failed for method: {method_name}")
            return self._create_abort_handler("Invalid or expired token")

        # Проверяем права доступа на основе роли пользователя
        if method_name in ADMIN_METHODS:
            if role != UserRole.ADMIN:
                logger.debug(
                    f"Admin role required for method: {method_name}, user role: {role}"
                )
                return self._create_abort_handler("Admin role required")

        elif method_name in ADMIN_OR_MODERATOR_METHODS:
            if role not in (UserRole.ADMIN, UserRole.MODERATOR):
                logger.debug(
                    f"Admin or Moderator role required for method: {method_name}, user role: {role}"
                )
                return self._create_abort_handler("Admin or Moderator role required")

        # Все проверки пройдены, продолжаем выполнение
        logger.debug(
            f"Authorization successful for method: {method_name}, role: {role}"
        )
        return await continuation(handler_call_details)

    async def _validate_token(self, token: str) -> Tuple[bool, Optional[UserRole]]:
        """
        Валидирует токен и возвращает результат валидации и роль пользователя.

        Args:
            token: JWT токен для валидации

        Returns:
            Tuple[bool, Optional[UserRole]]:
                - (True, UserRole) если валидация прошла успешно
                - (False, None) если валидация не прошла
        """
        # Проверяем blacklist
        is_blacklisted = await self.cache_repository.exists(f"blacklist:{token}")
        if is_blacklisted:
            logger.debug(f"Token is blacklisted: {token[:20]}...")
            return False, None

        # Создаем объект Token для верификации
        token_obj = Token.create(
            token_string=token,
            token_type=TokenType.BEARER,
            expires_in=0,
        )

        # Верифицируем токен
        payload = self.jwt_service.verify_token(token_obj)
        if not payload:
            logger.debug("Token verification failed: invalid or expired token")
            return False, None

        # Извлекаем username из payload
        username = payload.get("sub")
        if not username:
            logger.debug("Token payload missing 'sub' field")
            return False, None

        # Получаем пользователя из репозитория
        user = await self.user_repository.get_by_username(username)
        if not user:
            logger.debug(f"User not found: {username}")
            return False, None

        # Проверяем, что пользователь активен
        if not user.is_active:
            logger.debug(f"User is inactive: {username}")
            return False, None

        # Возвращаем успешный результат с ролью пользователя
        logger.debug(
            f"Token validation successful for user: {username}, role: {user.role}"
        )
        return True, user.role
