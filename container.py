from dependency_injector import containers, providers
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


from repository.redis_repository import RedisRepository
from repository.memory_adapter import MemoryRepository
from repository.user_repository import UserRepository

from service.auth_service import AuthService
from service.jwt_service import JWTService

from config import settings, logger
from database import create_async_engine


class LoggerContainer(containers.DeclarativeContainer):
    logger = providers.Object(logger)


class DatabaseContainer(containers.DeclarativeContainer):
    database_engine = providers.Singleton(
        create_async_engine,
        settings.postgres.url_asyncpg,
        echo=settings.postgres.echo,
        pool_size=settings.postgres.pool_size,
        max_overflow=settings.postgres.max_overflow,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_timeout=30,
    )

    session_factory = providers.Singleton(
        async_sessionmaker,
        bind=database_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    database_session = providers.Factory(
        lambda sf: sf(),  # Вызываем session_factory чтобы получить AsyncSession
        sf=session_factory,
    )


class RepositoriesContainer(containers.DeclarativeContainer):
    database = providers.DependenciesContainer()

    user_repository = providers.Factory(
        UserRepository,
        session=database.database_session,
    )

    cache_repository = providers.Singleton(RedisRepository)


class ServicesContainer(containers.DeclarativeContainer):
    repositories = providers.DependenciesContainer()
    logger = providers.DependenciesContainer()

    jwt_service = providers.Singleton(
        JWTService,
        access_token_expire_minutes=settings.security.access_token_expire_minutes,
        refresh_token_expire_minutes=settings.security.refresh_token_expire_minutes,
        secret_key=settings.security.secret_key,
        algorithm=settings.security.algorithm,
        logger=logger.logger,
    )

    auth_service = providers.Singleton(
        AuthService,
        cache_repository=repositories.cache_repository,
        user_repository=repositories.user_repository,
        jwt_service=jwt_service,
    )


class ApplicationContainer(containers.DeclarativeContainer):
    wiring_config = containers.WiringConfiguration(
        modules=["service.auth_service", "main"]
    )

    logger = providers.Container(LoggerContainer)
    database = providers.Container(DatabaseContainer)
    repositories = providers.Container(RepositoriesContainer, database=database)
    services = providers.Container(
        ServicesContainer, repositories=repositories, logger=logger
    )


container = ApplicationContainer()
