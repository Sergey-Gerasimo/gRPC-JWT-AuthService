from typing import Type
from repository.memory_adapter import MemoryRepository
from repository.redis_repository import RedisRepository
from config import settings, logger


class CacheRepositoryFactory:
    @staticmethod
    async def create_cache_repository():

        if not getattr(settings, "REDIS_URL", None):
            logger.warning("Redis URL not configured, using in-memory storage")
            return MemoryRepository()

        try:
            redis_repo = RedisRepository()

            is_connected = await redis_repo.ping()
            if not is_connected:
                raise ConnectionError("Redis ping failed")

            logger.info("Redis cache repository initialized successfully")
            return redis_repo

        except Exception as e:
            logger.warning(
                f"Redis connection failed: {e}. Using in-memory storage as fallback"
            )
            return MemoryRepository()
