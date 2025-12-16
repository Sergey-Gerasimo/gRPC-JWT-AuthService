from typing import Callable, Any
import grpc
from grpc import aio
from config import logger
from domain.exceptions import UnauthorizedError, ForbiddenError, InvalidTokenError
from domain.enums import UserRole
from service.jwt_service import JWTService
from domain.entities import Token
from repository.user_repository import UserRepository
from repository.redis_repository import RedisRepository


class _WrappedHandler:
    """Класс-обертка для handler'а с авторизацией"""

    def __init__(
        self,
        original_handler: Any,
        wrapped_unary_unary: Callable = None,
        wrapped_unary_stream: Callable = None,
        wrapped_stream_unary: Callable = None,
        wrapped_stream_stream: Callable = None,
    ):
        self.request_streaming = original_handler.request_streaming
        self.response_streaming = original_handler.response_streaming
        self.request_deserializer = original_handler.request_deserializer
        self.response_serializer = original_handler.response_serializer
        self._original_handler = original_handler

        # Устанавливаем обернутые методы
        if wrapped_unary_unary:
            self.unary_unary = wrapped_unary_unary
        if wrapped_unary_stream:
            self.unary_stream = wrapped_unary_stream
        if wrapped_stream_unary:
            self.stream_unary = wrapped_stream_unary
        if wrapped_stream_stream:
            self.stream_stream = wrapped_stream_stream


class AuthInterceptor(aio.ServerInterceptor):
    """Interceptor для проверки авторизации и прав доступа"""

    # Методы, которые не требуют авторизации
    PUBLIC_METHODS = {
        "/grpc.AuthService/authentication",
        "/grpc.AuthService/registrate",
        "/grpc.AuthService/refresh_token",
        "/grpc.AuthService/verify",
    }

    # Методы, требующие только авторизации (любой авторизованный пользователь)
    AUTHENTICATED_METHODS = {
        "/grpc.AuthService/get_user",
        "/grpc.AuthService/logout",
        "/grpc.AuthService/change_password",
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

    def __init__(
        self,
        jwt_service: JWTService,
        user_repository: UserRepository,
        cache_repository: RedisRepository,
    ):
        self.jwt_service = jwt_service
        self.user_repository = user_repository
        self.cache_repository = cache_repository

    async def intercept_service(
        self,
        continuation: Callable,
        handler_call_details: Any,
    ) -> Any:
        """Перехватывает вызовы методов и проверяет авторизацию"""
        method_name = handler_call_details.method
        logger.info(f"Method name: {method_name}")

        # Публичные методы - пропускаем без проверки
        if method_name in self.PUBLIC_METHODS:
            return await continuation(handler_call_details)

        # Для остальных методов нужна авторизация
        handler = await continuation(handler_call_details)

        if handler is None:
            return None

        return self._wrap_handler(handler, method_name)

    async def _check_auth(self, context, method_name: str):
        """Общая логика проверки авторизации и прав доступа"""
        # Правильно извлекаем метаданные - invocation_metadata() возвращает кортеж кортежей
        metadata_dict = {}
        for key, value in context.invocation_metadata():
            metadata_dict[key.lower()] = value

        token_string = metadata_dict.get("authorization") or metadata_dict.get("token")

        # Убираем префикс "Bearer " если есть
        if token_string and token_string.startswith("Bearer "):
            token_string = token_string[7:]

        if not token_string:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("Authorization token required")
            raise UnauthorizedError("Authorization token required")

        # Создаем объект Token для проверки
        token = Token.create(
            token_string=token_string,
            token_type=None,
            expires_in=0,
        )

        # Проверяем blacklist
        is_blacklisted = await self.cache_repository.exists(f"blacklist:{token_string}")
        if is_blacklisted:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("Token is blacklisted")
            raise InvalidTokenError("Token is blacklisted")

        # Верифицируем токен
        payload = self.jwt_service.verify_token(token)
        if not payload:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("Invalid or expired token")
            raise InvalidTokenError("Invalid or expired token")

        username = payload.get("sub")
        if not username:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("Invalid token payload")
            raise InvalidTokenError("Invalid token payload")

        # Получаем пользователя для проверки роли
        user = await self.user_repository.get_by_username(username)
        if not user or not user.is_active:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("User not found or inactive")
            raise UnauthorizedError("User not found or inactive")

        # Проверяем права доступа
        if method_name in self.ADMIN_METHODS:
            if user.role != UserRole.ADMIN:
                context.set_code(grpc.StatusCode.PERMISSION_DENIED)
                context.set_details("Admin role required")
                raise ForbiddenError("Admin role required")

        elif method_name in self.ADMIN_OR_MODERATOR_METHODS:
            if user.role not in (UserRole.ADMIN, UserRole.MODERATOR):
                context.set_code(grpc.StatusCode.PERMISSION_DENIED)
                context.set_details("Admin or Moderator role required")
                raise ForbiddenError("Admin or Moderator role required")

        # Сохраняем информацию о пользователе в контекст
        context.user = user
        context.username = username

    def _wrap_handler(self, handler: Any, method_name: str):
        """Обертывает обработчик для проверки авторизации"""

        # unary_unary - обычная функция с return
        async def wrapped_unary_unary(request, context):
            await self._check_auth(context, method_name)
            return await handler.unary_unary(request, context)

        # unary_stream - async generator с yield
        async def wrapped_unary_stream(request, context):
            await self._check_auth(context, method_name)
            async for response in handler.unary_stream(request, context):
                yield response

        # stream_unary - обычная функция с return
        async def wrapped_stream_unary(request_iterator, context):
            await self._check_auth(context, method_name)
            return await handler.stream_unary(request_iterator, context)

        # stream_stream - async generator с yield
        async def wrapped_stream_stream(request_iterator, context):
            await self._check_auth(context, method_name)
            async for response in handler.stream_stream(request_iterator, context):
                yield response

        # Создаем обертку для handler'а с нужными методами
        if handler.request_streaming and handler.response_streaming:
            return _WrappedHandler(handler, wrapped_stream_stream=wrapped_stream_stream)
        elif handler.request_streaming:
            return _WrappedHandler(handler, wrapped_stream_unary=wrapped_stream_unary)
        elif handler.response_streaming:
            return _WrappedHandler(handler, wrapped_unary_stream=wrapped_unary_stream)
        else:
            return _WrappedHandler(handler, wrapped_unary_unary=wrapped_unary_unary)
