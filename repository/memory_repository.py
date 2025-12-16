from typing import Any, Dict, Optional, Set, List
import asyncio
from datetime import datetime, timedelta
from config import logger


class MemoryRepository:
    """
    In-memory хранилище с TTL поддержкой.
    Аналог Redis, но работает в памяти процесса.
    """

    _instance = None
    _storage: Dict[str, Dict[str, Any]] = (
        {}
    )  # {key: {'value': value, 'expire_at': timestamp}}
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MemoryRepository, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if getattr(self, "_cleanup_task_started", False):
            return
        self._cleanup_task_started = True
        loop = asyncio.get_event_loop()
        self._cleanup_task = loop.create_task(self._cleanup_expired())

    async def _cleanup_expired(self):
        """Фоновая задача для очистки просроченных записей"""
        while True:
            await asyncio.sleep(60)  # Проверяем каждую минуту
            await self._remove_expired()

    async def _remove_expired(self):
        """Удаляет просроченные записи"""
        async with self._lock:
            now = datetime.now()
            expired_keys = [
                key
                for key, data in self._storage.items()
                if data.get("expire_at") and data["expire_at"] < now
            ]
            for key in expired_keys:
                del self._storage[key]
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired keys")

    def _calculate_expire_at(self, expire_seconds: Optional[int]) -> Optional[datetime]:
        """Вычисляет время истечения"""
        if expire_seconds is None:
            return None
        return datetime.now() + timedelta(seconds=expire_seconds)

    async def ping(self) -> bool:
        """Проверка доступности хранилища"""
        return True

    async def set(self, key: str, value: Any, expire: Optional[int] = None) -> bool:
        """
        Сохраняет значение по ключу с опциональным TTL.

        Args:
            key: Ключ
            value: Значение
            expire: TTL в секундах

        Returns:
            bool: True если успешно
        """
        async with self._lock:
            self._storage[key] = {
                "value": value,
                "expire_at": self._calculate_expire_at(expire),
            }
        return True

    async def setex(self, key: str, time: int, value: Any) -> bool:
        """
        Сохраняет значение с TTL.

        Args:
            key: Ключ
            time: TTL в секундах
            value: Значение

        Returns:
            bool: True если успешно
        """
        return await self.set(key, value, time)

    async def get(self, key: str) -> Optional[str]:
        """
        Получает значение по ключу.

        Args:
            key: Ключ

        Returns:
            Optional[str]: Значение или None если не найдено или просрочено
        """
        async with self._lock:
            data = self._storage.get(key)
            if not data:
                return None

            # Проверяем не просрочено ли значение
            if data.get("expire_at") and data["expire_at"] < datetime.now():
                del self._storage[key]
                return None

            return data["value"]

    async def delete(self, *keys: str) -> int:
        """
        Удаляет ключи.

        Args:
            keys: Ключи для удаления

        Returns:
            int: Количество удаленных ключей
        """
        async with self._lock:
            deleted = 0
            for key in keys:
                if key in self._storage:
                    del self._storage[key]
                    deleted += 1
            return deleted

    async def exists(self, key: str) -> bool:
        """
        Проверяет существование ключа.

        Args:
            key: Ключ

        Returns:
            bool: True если ключ существует и не просрочен
        """
        async with self._lock:
            data = self._storage.get(key)
            if not data:
                return False

            # Проверяем не просрочено ли значение
            if data.get("expire_at") and data["expire_at"] < datetime.now():
                del self._storage[key]
                return False

            return True

    async def hset(self, key: str, mapping: Dict[str, Any]) -> int:
        """
        Устанавливает значения в hash.

        Args:
            key: Ключ hash
            mapping: Словарь значений

        Returns:
            int: Количество установленных полей
        """
        async with self._lock:
            current_hash = self._storage.get(key, {}).get("value", {})
            if not isinstance(current_hash, dict):
                current_hash = {}

            current_hash.update(mapping)
            self._storage[key] = {
                "value": current_hash,
                "expire_at": None,  # Hash не имеет TTL по умолчанию
            }
            return len(mapping)

    async def hgetall(self, key: str) -> Dict[str, Any]:
        """
        Получает все поля hash.

        Args:
            key: Ключ hash

        Returns:
            Dict[str, Any]: Словарь всех полей
        """
        async with self._lock:
            data = self._storage.get(key)
            if not data:
                return {}

            value = data["value"]
            if not isinstance(value, dict):
                return {}

            return value

    async def expire(self, key: str, seconds: int) -> bool:
        """
        Устанавливает TTL для ключа.

        Args:
            key: Ключ
            seconds: TTL в секундах

        Returns:
            bool: True если ключ существует
        """
        async with self._lock:
            if key not in self._storage:
                return False

            self._storage[key]["expire_at"] = self._calculate_expire_at(seconds)
            return True

    async def incr(self, key: str) -> int:
        """
        Инкрементирует числовое значение.

        Args:
            key: Ключ

        Returns:
            int: Новое значение
        """
        async with self._lock:
            current_value = await self.get(key)
            if current_value is None:
                new_value = 1
            else:
                try:
                    new_value = int(current_value) + 1
                except (ValueError, TypeError):
                    new_value = 1

            self._storage[key] = {"value": str(new_value), "expire_at": None}
            return new_value

    async def lpush(self, key: str, *values: Any) -> int:
        """
        Добавляет значения в начало списка.

        Args:
            key: Ключ списка
            values: Значения для добавления

        Returns:
            int: Длина списка после добавления
        """
        async with self._lock:
            current_list = self._storage.get(key, {}).get("value", [])
            if not isinstance(current_list, list):
                current_list = []

            # Добавляем в начало
            for value in reversed(values):
                current_list.insert(0, value)

            self._storage[key] = {"value": current_list, "expire_at": None}
            return len(current_list)

    async def rpop(self, key: str) -> Optional[str]:
        """
        Удаляет и возвращает последний элемент списка.

        Args:
            key: Ключ списка

        Returns:
            Optional[str]: Последний элемент или None
        """
        async with self._lock:
            current_list = self._storage.get(key, {}).get("value", [])
            if not isinstance(current_list, list) or not current_list:
                return None

            value = current_list.pop()
            self._storage[key] = {"value": current_list, "expire_at": None}
            return value

    async def sadd(self, key: str, *members: Any) -> int:
        """
        Добавляет элементы в множество.

        Args:
            key: Ключ множества
            members: Элементы для добавления

        Returns:
            int: Количество добавленных элементов
        """
        async with self._lock:
            current_set = self._storage.get(key, {}).get("value", set())
            if not isinstance(current_set, set):
                current_set = set()

            added = 0
            for member in members:
                if member not in current_set:
                    current_set.add(member)
                    added += 1

            self._storage[key] = {"value": current_set, "expire_at": None}
            return added

    async def smembers(self, key: str) -> Set:
        """
        Получает все элементы множества.

        Args:
            key: Ключ множества

        Returns:
            Set: Множество элементов
        """
        async with self._lock:
            current_set = self._storage.get(key, {}).get("value", set())
            if not isinstance(current_set, set):
                return set()

            return current_set

    async def ttl(self, key: str) -> int:
        """
        Получает оставшееся время жизни ключа в секундах.

        Args:
            key: Ключ

        Returns:
            int: TTL в секундах, -1 если нет TTL, -2 если ключ не существует
        """
        async with self._lock:
            data = self._storage.get(key)
            if not data:
                return -2

            expire_at = data.get("expire_at")
            if not expire_at:
                return -1

            now = datetime.now()
            if expire_at < now:
                del self._storage[key]
                return -2

            return int((expire_at - now).total_seconds())

    async def keys(self, pattern: str = "*") -> List[str]:
        """
        Получает ключи по шаблону (простая реализация).

        Args:
            pattern: Шаблон (поддерживает только *)

        Returns:
            List[str]: Список ключей
        """
        async with self._lock:
            all_keys = list(self._storage.keys())

            if pattern == "*":
                return all_keys

            # Простая фильтрация по префиксу/суффиксу
            if pattern.startswith("*"):
                suffix = pattern[1:]
                return [k for k in all_keys if k.endswith(suffix)]
            elif pattern.endswith("*"):
                prefix = pattern[:-1]
                return [k for k in all_keys if k.startswith(prefix)]
            else:
                return [k for k in all_keys if k == pattern]

    async def flushall(self) -> bool:
        """Очищает все данные"""
        async with self._lock:
            self._storage.clear()
            return True

    async def close(self):
        """Останавливает фоновые задачи"""
        if hasattr(self, "_cleanup_task"):
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass


# Глобальный экземпляр
memory_repo = MemoryRepository()
