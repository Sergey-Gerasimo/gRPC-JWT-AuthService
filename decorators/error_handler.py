from functools import wraps
from typing import Any, Callable
import grpc
from datetime import datetime
from logging import Logger


def grpc_error_handler(logger: Logger = None):

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request, context, *args, **kwargs) -> Any:
            try:
                return await func(self, request, context, *args, **kwargs)

            except grpc.RpcError:
                # Пробрасываем gRPC ошибки как есть
                raise

            except ValueError as e:
                # Бизнес-логика ошибки (неверные данные)
                if logger:
                    logger.warning(f"Business logic error in {func.__name__}: {e}")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(str(e))
                return self._create_error_response(func.__name__, str(e))

            except ConnectionError as e:
                # Ошибки подключения к внешним сервисам
                if logger:
                    logger.error(f"Connection error in {func.__name__}: {e}")
                context.set_code(grpc.StatusCode.UNAVAILABLE)
                context.set_details("Service temporarily unavailable")
                return self._create_error_response(func.__name__, "Service unavailable")

            except Exception as e:
                # Непредвиденные ошибки
                if logger:
                    logger.error(
                        f"Unexpected error in {func.__name__}: {e}", exc_info=True
                    )
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details("Internal server error")
                return self._create_error_response(
                    func.__name__, "Internal server error"
                )

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
        elif method_name in ["logout", "verify", "change_password"]:
            from grpc_generated import auth_pb2

            return auth_pb2.SuccessResponse(
                success=False, message=message, timestamp=datetime.now().isoformat()
            )
        elif method_name == "get_user":
            from grpc_generated import auth_pb2

            return auth_pb2.User()  # Пустой пользователь
        else:
            # Fallback для неизвестных методов
            return None
