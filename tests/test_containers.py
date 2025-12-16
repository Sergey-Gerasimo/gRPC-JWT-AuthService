"""
Tests to verify that Docker Compose containers are working correctly.
"""

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from repository.redis_repository import RedisRepository


async def test_postgres_container_responds(async_engine: AsyncEngine):
    """Test that PostgreSQL container is running and responding."""
    async with async_engine.begin() as conn:
        result = await conn.execute(text("SELECT 1 as test"))
        row = result.fetchone()
        assert row is not None
        assert row[0] == 1


async def test_postgres_container_version(async_engine: AsyncEngine):
    """Test that we can get PostgreSQL version."""
    async with async_engine.begin() as conn:
        result = await conn.execute(text("SELECT version()"))
        row = result.fetchone()
        assert row is not None
        version = row[0]
        assert "PostgreSQL" in version
        assert "15" in version  # We're using postgres:15


async def test_redis_container_responds(redis_repository: RedisRepository):
    """Test that Redis container is running and responding."""
    # Test ping
    is_connected = await redis_repository.ping()
    assert is_connected is True


async def test_redis_container_operations(redis_repository: RedisRepository):
    """Test basic Redis operations."""
    # Test set/get
    test_key = "test:container:key"
    test_value = "test_value_123"

    await redis_repository.set(test_key, test_value)
    retrieved_value = await redis_repository.get(test_key)

    assert retrieved_value == test_value

    # Cleanup
    await redis_repository.delete(test_key)

    # Verify deletion
    exists = await redis_repository.exists(test_key)
    assert exists is False


async def test_postgres_and_redis_together(
    async_engine: AsyncEngine, redis_repository: RedisRepository
):
    """Test that both containers work together."""
    # PostgreSQL operation
    async with async_engine.begin() as conn:
        result = await conn.execute(text("SELECT current_database()"))
        db_name = result.scalar()
        assert db_name == "auth_db"  # Исправлено: используем auth_db вместо test_db

    # Redis operation
    is_connected = await redis_repository.ping()
    assert is_connected is True

    # Combined test: store result from PostgreSQL in Redis
    async with async_engine.begin() as conn:
        result = await conn.execute(text("SELECT current_database()"))
        db_name = result.scalar()

    await redis_repository.set("test:db_name", db_name)
    cached_db_name = await redis_repository.get("test:db_name")

    assert cached_db_name == db_name

    # Cleanup
    await redis_repository.delete("test:db_name")
