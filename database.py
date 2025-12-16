from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    AsyncEngine,
    async_sessionmaker,
)
from sqlalchemy.orm import DeclarativeBase

from config import settings, logger


async_engine = create_async_engine(
    settings.postgres.url_asyncpg,
    echo=True if settings.log.debug else False,
    pool_size=settings.postgres.pool_size,
    max_overflow=settings.postgres.max_overflow,
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_timeout=30,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    repr_cols_num = 3
    repr_cols = tuple()

    def __repr__(self):
        """Relationships не используются в repr(), т.к. могут вести к неожиданным подгрузкам"""
        cols = []
        for idx, col in enumerate(self.__table__.columns.keys()):
            if col in self.repr_cols or idx < self.repr_cols_num:
                cols.append(f"{col}={getattr(self, col)}")

        return f"<{self.__class__.__name__} {', '.join(cols)}>"


async def create_tables(async_engine: AsyncEngine) -> None:
    logger.info("Stargin database tables creation...")

    try:
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created successfully")

    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


async def drop_tables(async_engine: AsyncEngine) -> None:
    logger.info("Starting database tables drop...")

    try:
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            logger.info("Database tables dropped successfully")

    except Exception as e:
        logger.error(f"Failed to drop database tables: {e}")
        raise
