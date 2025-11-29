import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from loguru import logger


class LoguruInterceptHandler(logging.Handler):
    """Перехватывает логи стандартного logging и перенаправляет в loguru"""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


class GRPCLoggerConfig:
    """Конфигурация логгера для gRPC приложений"""

    # Форматы логов
    CONSOLE_FORMAT = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    JSON_FORMAT = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | "
        "{name}:{function}:{line} | {message}"
    )

    # gRPC-specific форматы
    GRPC_CONSOLE_FORMAT = (
        "<magenta>{time:YYYY-MM-DD HH:mm:ss.SSS}</magenta> | "
        "<level>{level: <8}</level> | "
        "<cyan>gRPC</cyan> | "
        "<level>{message}</level>"
    )

    GRPC_ACCESS_FORMAT = (
        "<blue>{time:YYYY-MM-DD HH:mm:ss.SSS}</blue> | "
        "gRPC | {extra[method]} | {extra[service]} | "
        "duration: {extra[duration]:.3f}s | status: {extra[status]}"
    )

    @staticmethod
    def _ensure_logs_directory() -> None:
        """Создает директорию для логов если не существует"""
        Path("logs").mkdir(exist_ok=True)

    @staticmethod
    def _configure_console_logging(level: str, debug: bool) -> None:
        """Настраивает консольный вывод"""
        logger.add(
            sys.stderr,
            format=GRPCLoggerConfig.CONSOLE_FORMAT,
            level=level,
            colorize=True,
            backtrace=debug,
            diagnose=debug,
            filter=lambda record: "grpc" not in record["name"].lower(),
        )

        # Отдельный обработчик для gRPC логов в консоли
        logger.add(
            sys.stderr,
            format=GRPCLoggerConfig.GRPC_CONSOLE_FORMAT,
            level=level,
            colorize=True,
            backtrace=debug,
            diagnose=debug,
            filter=lambda record: "grpc" in record["name"].lower(),
        )

    @staticmethod
    def _configure_file_logging(level: str, debug: bool, log_format: str) -> None:
        """Настраивает файловый вывод"""
        if not debug:
            file_format = (
                GRPCLoggerConfig.JSON_FORMAT
                if log_format == "json"
                else GRPCLoggerConfig.CONSOLE_FORMAT
            )

            # Основной лог файл
            logger.add(
                "logs/app.log",
                rotation="50 MB",
                retention="30 days",
                compression="gz",
                format=file_format,
                level=level,
                serialize=(log_format == "json"),
                backtrace=True,
                diagnose=False,
            )

        # Лог ошибок
        logger.add(
            "logs/error.log",
            rotation="10 MB",
            retention="15 days",
            compression="gz",
            level="ERROR",
            format=GRPCLoggerConfig.JSON_FORMAT,
            serialize=True,
            backtrace=True,
            diagnose=True,
        )

        # gRPC access log
        logger.add(
            "logs/grpc_access.log",
            rotation="20 MB",
            retention="7 days",
            compression="gz",
            format=GRPCLoggerConfig.JSON_FORMAT,
            level="INFO",
            serialize=True,
            filter=lambda record: "grpc.access" in record["name"].lower(),
        )

    @staticmethod
    def _configure_intercept_handler(level: str) -> None:
        """Настраивает перехват стандартного logging"""
        intercept_handler = LoguruInterceptHandler()

        # Корневой логгер
        logging.root.handlers = [intercept_handler]
        logging.root.setLevel(getattr(logging, level))

        # gRPC-specific логгеры
        grpc_loggers = [
            "grpc",
            "grpc.aio",
            "grpc_channelz",
            "grpc.reflection",
        ]

        # Общие логгеры
        common_loggers = [
            "uvicorn",
            "uvicorn.access",
            "uvicorn.error",
            "fastapi",
            "sqlalchemy",
            "aiosqlite",
        ]

        # Настраиваем все логгеры
        for logger_name in grpc_loggers + common_loggers:
            logging_logger = logging.getLogger(logger_name)
            logging_logger.handlers = [intercept_handler]
            logging_logger.setLevel(getattr(logging, level))
            logging_logger.propagate = False

    @staticmethod
    def configure(
        log_level: str = "INFO",
        debug: bool = False,
        log_format: str = "json",
        enable_grpc_access_log: bool = True,
    ) -> None:
        """
        Конфигурирует логгер для gRPC приложения

        Args:
            log_level: Уровень логирования (DEBUG, INFO, WARNING, ERROR)
            debug: Режим отладки
            log_format: Формат логов (json, console)
            enable_grpc_access_log: Включить логирование gRPC запросов
        """
        # Удаляем стандартные обработчики
        logger.remove()

        # Создаем директорию для логов
        GRPCLoggerConfig._ensure_logs_directory()

        # Настраиваем вывод
        GRPCLoggerConfig._configure_console_logging(log_level, debug)
        GRPCLoggerConfig._configure_file_logging(log_level, debug, log_format)
        GRPCLoggerConfig._configure_intercept_handler(log_level)

        # Логируем успешную конфигурацию
        logger.info(
            "gRPC logger configured",
            extra={
                "level": log_level,
                "debug": debug,
                "format": log_format,
                "grpc_access_log": enable_grpc_access_log,
            },
        )


# Утилиты для gRPC логирования
class GRPCLoggingUtils:
    """Утилиты для логирования gRPC событий"""

    @staticmethod
    def log_grpc_request(
        method: str,
        service: str,
        duration: float,
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Логирует gRPC запрос"""
        extra_data = {
            "method": method,
            "service": service,
            "duration": duration,
            "status": status,
            "type": "grpc_request",
        }

        if metadata:
            extra_data["metadata"] = metadata

        logger.bind(**extra_data).info("gRPC request completed")

    @staticmethod
    def log_grpc_error(
        method: str, service: str, error: str, details: Optional[str] = None
    ) -> None:
        """Логирует gRPC ошибку"""
        extra_data = {
            "method": method,
            "service": service,
            "error": error,
            "type": "grpc_error",
        }

        if details:
            extra_data["details"] = details

        logger.bind(**extra_data).error("gRPC error occurred")

    @staticmethod
    def get_grpc_logger(service_name: str):
        """Возвращает логгер для конкретного gRPC сервиса"""
        return logger.bind(service=service_name, type="grpc_service")


# Пример использования
if __name__ == "__main__":
    # Конфигурация
    GRPCLoggerConfig.configure(log_level="DEBUG", debug=True, log_format="json")

    # Пример логирования gRPC событий
    grpc_logger = GRPCLoggingUtils.get_grpc_logger("UserService")
    grpc_logger.info("Service started")

    GRPCLoggingUtils.log_grpc_request(
        method="GetUser",
        service="UserService",
        duration=0.125,
        status="OK",
        metadata={"user_id": "123"},
    )


app_logger = logger
