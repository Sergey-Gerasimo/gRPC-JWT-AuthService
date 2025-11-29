from .env_settings import settings
from .logger_settings import (
    GRPCLoggerConfig,
    GRPCLoggingUtils,
    LoguruInterceptHandler,
    logger,
)

SETTINGS_IS_LOAD = False


def configure_application() -> None:
    """
    Конфигурирует приложение - загружает настройки и настраивает логирование
    """
    global SETTINGS_IS_LOAD

    if SETTINGS_IS_LOAD:
        return

    # Загружаем настройки окружения
    env_settings = settings

    # Конфигурируем логирование
    GRPCLoggerConfig.configure(
        log_level=env_settings.log.log_level,
        debug=env_settings.log.debug,
        log_format=env_settings.log.log_format,
        enable_grpc_access_log=env_settings.log.enable_grpc_access_log,
    )

    SETTINGS_IS_LOAD = True

    # Логируем успешную загрузку конфигурации
    from loguru import logger

    logger.info(
        "Application configuration loaded",
        extra={
            "debug_mode": env_settings.log.debug,
            "log_level": env_settings.log.log_level,
            "log_format": env_settings.log.log_format,
        },
    )


# Автоматическая конфигурация при импорте модуля
if not SETTINGS_IS_LOAD:
    configure_application()


# Импорты для удобного доступа
__all__ = [
    "settings",
    "GRPCLoggerConfig",
    "GRPCLoggingUtils",
    "LoguruInterceptHandler",
    "configure_application",
    "SETTINGS_IS_LOAD",
    "logger",
]


# Версия пакета
__version__ = "1.0.0"
__author__ = "Your Name"
__description__ = "gRPC JWT Authentication Service"
