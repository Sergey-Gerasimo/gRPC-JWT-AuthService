from typing import Any, AsyncGenerator, Dict, Optional
from .memory_repository import memory_repo


class MemoryConnectionPool:
    """Адаптер для совместимости с Redis интерфейсом"""

    @classmethod
    def get_pool(cls):
        return cls()

    @classmethod
    async def close_pool(cls):
        await memory_repo.close()


class MemoryClient:
    def __init__(self):
        self.client = memory_repo

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


async def get_memory_client() -> AsyncGenerator[MemoryClient, None]:
    client = MemoryClient()
    try:
        yield client.client
    finally:
        pass


class MemoryRepository:
    """Статические методы для совместимости с RedisRepository"""

    @staticmethod
    async def ping() -> bool:
        return await memory_repo.ping()

    @staticmethod
    async def set(key: str, value: Any, expire: Optional[int] = None) -> bool:
        return await memory_repo.set(key, value, expire)

    @staticmethod
    async def setex(key: str, time: int, value: Any) -> bool:
        return await memory_repo.setex(key, time, value)

    @staticmethod
    async def get(key: str) -> Optional[str]:
        return await memory_repo.get(key)

    @staticmethod
    async def delete(*keys: str) -> int:
        return await memory_repo.delete(*keys)

    @staticmethod
    async def exists(key: str) -> bool:
        return await memory_repo.exists(key)

    @staticmethod
    async def hset(key: str, mapping: Dict[str, Any]) -> int:
        return await memory_repo.hset(key, mapping)

    @staticmethod
    async def hgetall(key: str) -> Dict[str, Any]:
        return await memory_repo.hgetall(key)

    @staticmethod
    async def expire(key: str, seconds: int) -> bool:
        return await memory_repo.expire(key, seconds)

    @staticmethod
    async def incr(key: str) -> int:
        return await memory_repo.incr(key)

    @staticmethod
    async def lpush(key: str, *values: Any) -> int:
        return await memory_repo.lpush(key, *values)

    @staticmethod
    async def rpop(key: str) -> Optional[str]:
        return await memory_repo.rpop(key)

    @staticmethod
    async def sadd(key: str, *members: Any) -> int:
        return await memory_repo.sadd(key, *members)

    @staticmethod
    async def smembers(key: str) -> set:
        return await memory_repo.smembers(key)
