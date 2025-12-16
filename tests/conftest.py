import sys
import time
import os
import pytest
import pytest_asyncio
from pathlib import Path
from testcontainers.compose import DockerCompose
import asyncpg
import grpc
import warnings
from typing import AsyncGenerator

PROJECT_ROOT = Path(__file__).parent.parent

# Добавляем корень проекта в sys.path для импорта модулей
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Глобальная переменная для хранения ссылки на docker_compose
_docker_compose_instance = None

# Глобальная переменная для включения логирования в тестах
# Можно установить через переменную окружения ENABLE_TEST_LOGS=true или через pytest опцию --enable-logs
ENABLE_TEST_LOGS = os.getenv("ENABLE_TEST_LOGS", "false").lower() == "true"

from config import logger
from config.env_settings import Settings
from grpc_generated.auth_pb2_grpc import AuthServiceStub
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
from repository.redis_repository import RedisRepository, RedisConnectionPool
import redis.asyncio as redis_async


def pytest_addoption(parser):
    """Добавляет опции командной строки для pytest"""
    parser.addoption(
        "--enable-logs",
        action="store_true",
        default=False,
        help="Включить логирование во время тестов (по умолчанию только при ошибках)",
    )
    parser.addoption(
        "--test-log-level",
        action="store",
        default="DEBUG",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Уровень логирования для тестов (по умолчанию: DEBUG)",
    )


def _setup_logging(request=None, log_level: str = "ERROR"):
    """Настраивает логирование для тестов"""
    global ENABLE_TEST_LOGS

    logger.remove()  # Удаляем все обработчики

    # Проверяем флаг включения логов через глобальную переменную или pytest опцию
    enable_logs = ENABLE_TEST_LOGS
    if request:
        enable_logs = enable_logs or request.config.getoption(
            "--enable-logs", default=False
        )
        if request.config.getoption("--test-log-level"):
            log_level = request.config.getoption("--test-log-level")

    if enable_logs:
        # Включаем логирование на указанном уровне
        logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
            level=log_level,
            colorize=True,
        )
    else:
        # По умолчанию только ERROR и выше
        logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
            level="ERROR",
            colorize=True,
            filter=lambda record: record["level"].name
            in ("ERROR", "CRITICAL"),  # Только ошибки
        )


# Настраиваем логирование при импорте модуля (базовый уровень)
if ENABLE_TEST_LOGS:
    _setup_logging()
else:
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
        level="ERROR",
        colorize=True,
    )


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    """Настраивает логирование при конфигурации pytest"""
    global ENABLE_TEST_LOGS

    # Обновляем глобальную переменную с учетом опции командной строки
    ENABLE_TEST_LOGS = ENABLE_TEST_LOGS or config.getoption(
        "--enable-logs", default=False
    )

    # Отключаем live logging pytest, если флаг выключен
    if not ENABLE_TEST_LOGS:
        # Отключаем встроенное live logging pytest
        config.option.log_cli = False
        config.option.log_cli_level = None
        config.option.log_cli_format = None
        config.option.log_cli_date_format = None

    # Переконфигурируем логирование с учетом опций командной строки
    log_level = config.getoption("--test-log-level", default="DEBUG")

    if ENABLE_TEST_LOGS:
        _setup_logging(request=None, log_level=log_level)


# Хук для включения логирования при падении теста
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Включает логирование при падении теста и выводит логи Docker контейнеров"""
    global _docker_compose_instance

    outcome = yield
    report = outcome.get_result()

    # Если тест упал, включаем логирование на уровне DEBUG (если не включено через флаг)
    if report.failed:
        if not ENABLE_TEST_LOGS:
            # Включаем логирование только если оно не было включено через флаг
            logger.remove()
            logger.add(
                sys.stderr,
                format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
                level="DEBUG",
                colorize=True,
            )
        # Логируем ошибку
        if call.excinfo:
            logger.error(f"Test failed: {item.name}", exc_info=call.excinfo)

        # Получаем логи из Docker контейнеров
        docker_compose = _docker_compose_instance
        if docker_compose:
            try:
                print("\n" + "=" * 80)
                print("DOCKER CONTAINER LOGS (при ошибке теста)")
                print("=" * 80)

                # Список сервисов для получения логов
                services = ["auth-service", "db", "redis"]

                for service_name in services:
                    try:
                        stdout, stderr = docker_compose.get_logs(service_name)
                        print(f"\n--- Логи контейнера: {service_name} ---")
                        if stdout:
                            # Выводим последние 10000 символов логов для лучшего контекста
                            logs = stdout[-10000:] if len(stdout) > 10000 else stdout
                            print(logs)
                        if stderr:
                            print(f"\n--- Ошибки контейнера: {service_name} ---")
                            errors = stderr[-10000:] if len(stderr) > 10000 else stderr
                            print(errors)
                    except Exception as e:
                        print(f"\nНе удалось получить логи для {service_name}: {e}")

                print("\n" + "=" * 80)
            except Exception as e:
                print(f"\nНе удалось получить логи Docker контейнеров: {e}")


@pytest.fixture(scope="session")
def docker_compose():
    """Фикстура для управления Docker Compose окружением."""
    global _docker_compose_instance

    compose = DockerCompose(
        str(PROJECT_ROOT),
        compose_file_name="docker-compose.yaml",
        pull=False,
        build=True,  # Собираем образ
    )

    # Сохраняем ссылку на docker_compose для использования в хуках
    _docker_compose_instance = compose

    with compose:
        # Ждем готовности PostgreSQL
        max_retries = 60
        for i in range(max_retries):
            try:
                stdout, stderr, exit_code = compose.exec_in_container(
                    service_name="db",
                    command=["pg_isready", "-U", "user"],
                )
                if exit_code == 0:
                    break
            except Exception as e:
                if i == max_retries - 1:
                    raise RuntimeError(f"PostgreSQL не готов после ожидания: {e}")
            if i == max_retries - 1:
                raise RuntimeError("PostgreSQL не готов после ожидания")
            time.sleep(1)

        # Ждем запуска сервиса - проверяем логи
        print("Ожидание запуска simulation_service...")
        max_retries = 120  # Увеличиваем время ожидания
        service_ready = False
        for i in range(max_retries):
            try:
                # Проверяем что контейнер запущен
                stdout, stderr, exit_code = compose.exec_in_container(
                    service_name="auth-service",
                    command=["python", "-c", "import sys; sys.exit(0)"],
                )
                # Проверяем gRPC порты для обоих сервисов
                channel_auth = grpc.insecure_channel("localhost:50051")
                try:
                    grpc.channel_ready_future(channel_auth).result(timeout=2)

                    channel_auth.close()
                    service_ready = True
                    print("gRPC сервисы готовы!")
                    break
                except Exception:
                    channel_auth.close()
            except Exception as e:
                if i % 10 == 0:  # Логируем каждые 10 попыток
                    print(f"Ожидание gRPC сервиса... попытка {i}/{max_retries}")
            if not service_ready:
                time.sleep(2)

        if not service_ready:
            # Пробуем получить логи сервиса для отладки
            try:
                stdout, stderr = compose.get_logs("simulation_service")
                print("Логи simulation_service:")
                print(stdout[:2000] if stdout else "Нет логов")
                if stderr:
                    print("Ошибки:")
                    print(stderr[:2000])
            except:
                pass
            raise RuntimeError("gRPC сервис не готов после ожидания")

        yield compose

        # Cleanup happens automatically when exiting context manager
        _docker_compose_instance = None


@pytest_asyncio.fixture(scope="function", autouse=True)
async def cleanup_database(docker_compose):
    """Очищает базу данных перед и после каждого теста."""
    # Используем прямые значения для подключения к тестовой БД
    db_host = "localhost"
    db_port = 5432
    db_user = "user"
    db_password = "password"
    db_name = "auth_db"

    async def cleanup_tables():
        """Вспомогательная функция для очистки таблиц."""
        conn = None
        try:
            conn = await asyncpg.connect(
                host=db_host,
                port=db_port,
                user=db_user,
                password=db_password,
                database=db_name,
                timeout=10,  # Таймаут для подключения
                command_timeout=10,  # Таймаут для выполнения команд
            )
            # Получаем список всех таблиц
            tables = await conn.fetch(
                """
                SELECT tablename FROM pg_tables 
                WHERE schemaname = 'public'
                """
            )

            if tables:
                # Очищаем все таблицы используя DELETE
                table_names = [t["tablename"] for t in tables]

                # Используем DELETE вместо TRUNCATE для избежания блокировок
                # DELETE не требует эксклюзивной блокировки и работает быстрее при наличии активных соединений
                for table_name in table_names:
                    await conn.execute(f'DELETE FROM "{table_name}"')
        except Exception as e:
            logger.error(f"Error cleaning up tables: {e}", exc_info=True)
            # Игнорируем ошибки если таблицы еще не созданы
            # (сервис создаст их при первом запуске)
            pass
        finally:
            if conn:
                try:
                    await conn.close()
                except Exception:
                    # Игнорируем ошибки при закрытии соединения
                    pass

    # Очищаем перед тестом
    await cleanup_tables()

    yield

    # Очищаем после теста
    await cleanup_tables()


@pytest.fixture(scope="session")
def grpc_channel(docker_compose):
    """Создает gRPC канал для подключения к db_manager сервису."""
    port = 50051  # Порт для db_manager сервиса
    channel = grpc.insecure_channel(f"localhost:{port}")

    # Ждем готовности канала
    max_retries = 30
    for i in range(max_retries):
        try:
            grpc.channel_ready_future(channel).result(timeout=5)
            break
        except Exception:
            if i < max_retries - 1:
                time.sleep(1)
            else:
                channel.close()
                raise

    yield channel
    channel.close()


@pytest.fixture(scope="function")
def auth_service_stub(grpc_channel):
    """Создает stub для SimulationDatabaseManager."""
    return AuthServiceStub(grpc_channel)


@pytest.fixture(scope="function")
def test_settings() -> Settings:
    """Создает настройки для тестов с подключением к Docker Compose контейнерам."""
    # Устанавливаем переменные окружения для подключения к контейнерам
    os.environ["POSTGRES_HOST"] = "localhost"
    os.environ["POSTGRES_PORT"] = "5432"
    os.environ["POSTGRES_USER"] = "user"
    os.environ["POSTGRES_PASSWORD"] = "password"
    os.environ["POSTGRES_DB"] = "auth_db"

    os.environ["REDIS_HOST"] = "localhost"
    os.environ["REDIS_PORT"] = "6379"
    os.environ["REDIS_PASSWORD"] = "redis_password"

    # Создаем новый экземпляр настроек
    return Settings()


# Флаг для создания таблиц только один раз
_tables_created = False


@pytest_asyncio.fixture(scope="function")
async def async_engine(test_settings: Settings) -> AsyncGenerator[AsyncEngine, None]:
    """Создает async SQLAlchemy engine для тестирования."""
    global _tables_created

    # Формируем PostgreSQL URL напрямую из переменных окружения
    postgres_host = os.environ.get("POSTGRES_HOST", "localhost")
    postgres_port = os.environ.get("POSTGRES_PORT", "5432")
    postgres_user = os.environ.get("POSTGRES_USER", "user")
    postgres_password = os.environ.get("POSTGRES_PASSWORD", "password")
    postgres_db = os.environ.get("POSTGRES_DB", "auth_db")

    db_url = f"postgresql+asyncpg://{postgres_user}:{postgres_password}@{postgres_host}:{postgres_port}/{postgres_db}"

    engine = create_async_engine(
        db_url,
        echo=False,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_timeout=30,
    )

    # Проверяем существование таблицы и создаем её только один раз
    if not _tables_created:
        from database import create_tables
        from sqlalchemy import text

        async with engine.begin() as conn:
            result = await conn.execute(
                text(
                    """
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = 'users'
                    );
                """
                )
            )
            table_exists = result.scalar()

        if not table_exists:
            await create_tables(engine)
        _tables_created = True

    yield engine

    # Cleanup
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def redis_repository(
    test_settings: Settings,
) -> AsyncGenerator[RedisRepository, None]:
    """Создает Redis репозиторий для тестирования."""
    # Сбрасываем пул соединений
    if RedisConnectionPool._pool is not None:
        try:
            await RedisConnectionPool.close_pool()
        except RuntimeError:
            # Event loop закрыт, просто сбрасываем
            pass
    RedisConnectionPool._pool = None

    # Создаем пул напрямую с настройками теста
    test_pool = redis_async.ConnectionPool.from_url(
        test_settings.redis.url,
        max_connections=test_settings.redis.max_connections,
        decode_responses=test_settings.redis.decode_responses,
        retry_on_timeout=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        health_check_interval=30,
    )

    # Устанавливаем пул напрямую
    RedisConnectionPool._pool = test_pool

    repository = RedisRepository()
    # Проверяем соединение
    is_connected = await repository.ping()
    if not is_connected:
        raise ConnectionError(
            f"Redis connection failed. Trying to connect to {test_settings.redis.host}:{test_settings.redis.port}"
        )

    yield repository

    # Cleanup
    try:
        await RedisConnectionPool.close_pool()
    except RuntimeError:
        # Event loop закрыт, просто сбрасываем пул
        pass
    finally:
        RedisConnectionPool._pool = None
