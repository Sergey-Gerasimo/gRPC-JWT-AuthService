from functools import wraps
from typing import Any, Callable
import grpc
from datetime import datetime
from logging import Logger
from domain.exceptions import (
    NotFoundError,
    InvalidArgumentError,
    AlreadyExistsError,
    UnauthorizedError,
    ForbiddenError,
    TooManyAuthenticationAttemptsError,
    InvalidTokenError,
)

from grpc_generated import auth_pb2

# Маппинг исключений на gRPC статус коды
_EXCEPTION_TO_STATUS_CODE = {
    TooManyAuthenticationAttemptsError: grpc.StatusCode.RESOURCE_EXHAUSTED,
    InvalidTokenError: grpc.StatusCode.INVALID_ARGUMENT,
    UnauthorizedError: grpc.StatusCode.PERMISSION_DENIED,
    ForbiddenError: grpc.StatusCode.PERMISSION_DENIED,
    NotFoundError: grpc.StatusCode.NOT_FOUND,
    InvalidArgumentError: grpc.StatusCode.INVALID_ARGUMENT,
    AlreadyExistsError: grpc.StatusCode.ALREADY_EXISTS,
}


def _handle_error(
    exception: Exception, context, logger: Logger = None
) -> auth_pb2.SuccessResponse:
    """
    Обрабатывает исключение и возвращает стандартный error response.

    Args:
        exception: Исключение для обработки
        context: gRPC контекст
        logger: Опциональный логгер для записи ошибок

    Returns:
        SuccessResponse с информацией об ошибке
    """
    # Получаем сообщение об ошибке
    error_message = getattr(exception, "message", str(exception))

    # Определяем статус код
    status_code = _EXCEPTION_TO_STATUS_CODE.get(
        type(exception), grpc.StatusCode.INTERNAL
    )

    # Для внутренних ошибок используем общее сообщение
    if status_code == grpc.StatusCode.INTERNAL:
        error_message = "Internal server error"
        if logger:
            logger.exception("Unhandled exception occurred", exc_info=exception)

    # Устанавливаем статус и детали в контекст
    context.set_code(status_code)
    context.set_details(error_message)

    # Возвращаем стандартный response
    return auth_pb2.SuccessResponse(
        success=False,
        message=error_message,
        timestamp=datetime.now().isoformat(),
    )


def grpc_error_handler(logger: Logger = None):
    """
    Декоратор для обработки исключений в gRPC методах.

    Args:
        logger: Опциональный логгер для записи ошибок

    Returns:
        Декоратор функции
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request, context, *args, **kwargs) -> Any:
            try:
                return await func(self, request, context, *args, **kwargs)
            except tuple(_EXCEPTION_TO_STATUS_CODE.keys()) as e:
                return _handle_error(e, context, logger)
            except Exception as e:
                return _handle_error(e, context, logger)

        return wrapper

    return decorator


class ErrorResponseMixin:
    """Mixin для создания стандартных error responses"""

    def _create_error_response(self, method_name: str, message: str):
        """
        Создает стандартный error response в зависимости от типа метода.
        """
        # Определяем тип возвращаемого значения по имени метода
        if method_name in ["authentication", "registrate", "refresh_token"]:
            from grpc_generated import auth_pb2

            return auth_pb2.AuthResponse(
                success=False, message=message, timestamp=datetime.now().isoformat()
            )
        elif method_name in ["logout", "verify", "change_password", "delete_user"]:
            from grpc_generated import auth_pb2

            return auth_pb2.SuccessResponse(
                success=False, message=message, timestamp=datetime.now().isoformat()
            )
        elif method_name in ["get_user", "get_user_by_username"]:
            from grpc_generated import auth_pb2

            return auth_pb2.User()  # Пустой пользователь
        elif method_name in ["create_user", "update_user"]:
            from grpc_generated import auth_pb2

            return auth_pb2.UserResponse(
                success=False, message=message, timestamp=datetime.now().isoformat()
            )
        elif method_name == "list_users":
            from grpc_generated import auth_pb2

            return auth_pb2.UsersResponse(
                success=False, message=message, timestamp=datetime.now().isoformat()
            )
        else:
            # Fallback для неизвестных методов
            return None
