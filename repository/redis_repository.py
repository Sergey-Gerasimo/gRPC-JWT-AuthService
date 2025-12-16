import json
import pickle
from typing import Any, AsyncGenerator, Dict, Optional
from pydantic import BaseModel
import redis.asyncio as redis

from config import settings, logger


class PydanticRedisSerializer:
    """Сериализатор для Pydantic моделей"""

    @staticmethod
    def serialize(value: Any) -> str:
        """Сериализация значения для Redis"""
        if isinstance(value, BaseModel):
            # Сериализуем Pydantic модель в JSON
            return json.dumps(
                {
                    "__pydantic__": True,
                    "class": value.__class__.__name__,
                    "module": value.__class__.__module__,
                    "data": value.model_dump(),
                }
            )
        elif isinstance(value, (dict, list, str, int, float, bool)) or value is None:
            # Стандартные типы сериализуем как есть
            return json.dumps(value)
        else:
            # Для сложных объектов используем pickle
            return pickle.dumps(value)

    @staticmethod
    def deserialize(serialized: str) -> Any:
        """Десериализация значения из Redis"""
        try:
            # Пытаемся десериализовать как JSON
            data = json.loads(serialized)

            # Проверяем, это Pydantic модель?
            if isinstance(data, dict) and data.get("__pydantic__"):
                class_name = data["class"]
                module_name = data["module"]

                # Динамически импортируем класс
                import importlib

                module = importlib.import_module(module_name)
                model_class = getattr(module, class_name)

                # Создаем экземпляр модели
                return model_class(**data["data"])

            return data

        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                # Пробуем pickle для бинарных данных
                return pickle.loads(
                    serialized.encode("latin-1")
                    if isinstance(serialized, str)
                    else serialized
                )
            except Exception as e:
                logger.warning(f"Failed to deserialize value: {e}")
                return serialized


class RedisConnectionPool:
    _pool: Optional[redis.ConnectionPool] = None

    @classmethod
    def get_pool(cls) -> redis.ConnectionPool:
        if cls._pool is not None:
            return cls._pool

        cls._pool = redis.ConnectionPool.from_url(
            settings.redis.url,
            max_connections=settings.redis.max_connections,
            decode_responses=settings.redis.decode_responses,
            retry_on_timeout=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            health_check_interval=30,
        )

        return cls._pool

    @classmethod
    async def close_pool(cls):
        if cls._pool is not None:
            await cls._pool.disconnect()
            cls._pool = None


class RedisClient:
    def __init__(self):
        self._client: Optional[redis.Redis] = None

    async def __aenter__(self) -> redis.Redis:
        pool = RedisConnectionPool.get_pool()
        self._client = redis.Redis(connection_pool=pool)
        return self._client

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.close()


async def get_redis_client() -> AsyncGenerator[redis.Redis, None]:
    pool = RedisConnectionPool.get_pool()
    client = redis.Redis(connection_pool=pool)
    try:
        await client.ping()
        yield client
    except redis.RedisError as e:
        logger.error(f"Redis connection error: {e}")
        raise Exception(f"Redis connection error: {e}")
    finally:
        await client.close()


class RedisRepository:
    def __init__(self):
        self.serializer = PydanticRedisSerializer()

    def _get_client(self) -> redis.Redis:
        pool = RedisConnectionPool.get_pool()
        return redis.Redis(connection_pool=pool)

    async def _execute_operation(self, operation, *args, **kwargs):
        """Универсальный метод для выполнения операций с клиентом"""
        client = self._get_client()
        try:
            return await operation(client, *args, **kwargs)
        except Exception as e:
            logger.error(f"Redis operation error: {e}")
            raise
        finally:
            await client.close()

    async def ping(self) -> bool:
        return await self._execute_operation(lambda client: client.ping())

    async def set(self, key: str, value: Any, expire: Optional[int] = None) -> bool:
        serialized_value = self.serializer.serialize(value)
        return await self._execute_operation(
            lambda client, k, v, ex: client.set(k, v, ex=ex),
            key,
            serialized_value,
            expire,
        )

    async def setex(self, key: str, time: int, value: Any) -> bool:
        serialized_value = self.serializer.serialize(value)
        return await self._execute_operation(
            lambda client, k, t, v: client.setex(k, t, v), key, time, serialized_value
        )

    async def get(self, key: str) -> Optional[Any]:
        result = await self._execute_operation(lambda client, k: client.get(k), key)
        if result is None:
            return None
        return self.serializer.deserialize(result)

    async def get_int(self, key: str) -> Optional[int]:
        """Get a raw integer value without deserialization (for counters)"""
        result = await self._execute_operation(lambda client, k: client.get(k), key)
        if result is None:
            return None
        try:
            # Try to parse as integer (handles both raw integers and JSON-encoded integers)
            if isinstance(result, int):
                return result
            if isinstance(result, str):
                # Try JSON first, then direct int conversion
                try:
                    parsed = json.loads(result)
                    if isinstance(parsed, int):
                        return parsed
                except (json.JSONDecodeError, ValueError):
                    pass
                # Direct int conversion for raw string integers
                return int(result)
            return int(result)
        except (ValueError, TypeError):
            # If deserialization fails, try the regular deserializer as fallback
            deserialized = self.serializer.deserialize(result)
            if isinstance(deserialized, int):
                return deserialized
            if isinstance(deserialized, str):
                return int(deserialized)
            raise ValueError(f"Cannot convert value to integer: {result}")

    async def delete(self, *keys: str) -> int:
        return await self._execute_operation(lambda client, k: client.delete(*k), keys)

    async def exists(self, key: str) -> bool:
        return (
            await self._execute_operation(lambda client, k: client.exists(k), key) > 0
        )

    async def hset(self, key: str, mapping: Dict[str, Any]) -> int:
        serialized_mapping = {
            field: self.serializer.serialize(value) for field, value in mapping.items()
        }
        return await self._execute_operation(
            lambda client, k, m: client.hset(k, mapping=m), key, serialized_mapping
        )

    async def hgetall(self, key: str) -> Dict[str, Any]:
        result = await self._execute_operation(lambda client, k: client.hgetall(k), key)
        if not result:
            return {}

        deserialized = {}
        for field, value in result.items():
            # Декодируем поле из bytes если нужно
            field_str = field.decode("utf-8") if isinstance(field, bytes) else field
            deserialized[field_str] = self.serializer.deserialize(value)

        return deserialized

    async def hget(self, key: str, field: str) -> Optional[Any]:
        result = await self._execute_operation(
            lambda client, k, f: client.hget(k, f), key, field
        )
        if result is None:
            return None
        return self.serializer.deserialize(result)

    async def expire(self, key: str, seconds: int) -> bool:
        return await self._execute_operation(
            lambda client, k, s: client.expire(k, s), key, seconds
        )

    async def incr(self, key: str) -> int:
        return await self._execute_operation(lambda client, k: client.incr(k), key)

    async def set_int(self, key: str, value: int, expire: Optional[int] = None) -> bool:
        """Set a raw integer value without serialization (for counters)"""
        return await self._execute_operation(
            lambda client, k, v, ex: client.set(k, v, ex=ex),
            key,
            value,
            expire,
        )

    async def lpush(self, key: str, *values: Any) -> int:
        serialized_values = [self.serializer.serialize(v) for v in values]
        return await self._execute_operation(
            lambda client, k, v: client.lpush(k, *v), key, serialized_values
        )

    async def rpop(self, key: str) -> Optional[Any]:
        result = await self._execute_operation(lambda client, k: client.rpop(k), key)
        if result is None:
            return None
        return self.serializer.deserialize(result)

    async def sadd(self, key: str, *members: Any) -> int:
        serialized_members = [self.serializer.serialize(m) for m in members]
        return await self._execute_operation(
            lambda client, k, m: client.sadd(k, *m), key, serialized_members
        )

    async def smembers(self, key: str) -> set:
        result = await self._execute_operation(
            lambda client, k: client.smembers(k), key
        )
        if not result:
            return set()

        deserialized = set()
        for member in result:
            deserialized.add(self.serializer.deserialize(member))

        return deserialized

    # Статические методы для обратной совместимости
    @staticmethod
    async def static_set(key: str, value: Any, expire: Optional[int] = None) -> bool:
        repo = RedisRepository()
        return await repo.set(key, value, expire)

    @staticmethod
    async def static_get(key: str) -> Optional[Any]:
        repo = RedisRepository()
        return await repo.get(key)

    @staticmethod
    async def static_delete(*keys: str) -> int:
        repo = RedisRepository()
        return await repo.delete(*keys)

    @staticmethod
    async def static_exists(key: str) -> bool:
        repo = RedisRepository()
        return await repo.exists(key)

    @staticmethod
    async def static_hset(key: str, mapping: Dict[str, Any]) -> int:
        repo = RedisRepository()
        return await repo.hset(key, mapping)

    @staticmethod
    async def static_hgetall(key: str) -> Dict[str, Any]:
        repo = RedisRepository()
        return await repo.hgetall(key)

    @staticmethod
    async def static_incr(key: str) -> int:
        repo = RedisRepository()
        return await repo.incr(key)
