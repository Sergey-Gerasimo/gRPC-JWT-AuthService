from typing import Optional, List
from uuid import UUID
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from domain.entities import User
from domain.enums import UserRole
from domain.values import HashedPasswordSHA256
from models import User as UserModel


class UserRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    def _to_entity(self, model: UserModel) -> User:
        username = model.username
        password_hash = HashedPasswordSHA256(value=model.hashed_password)
        role = (
            UserRole(model.role.value)
            if hasattr(model.role, "value")
            else UserRole(model.role)
        )

        return User(
            user_id=str(model.user_id),
            username=username,
            password_hash=password_hash,
            role=role,
            is_active=model.is_active,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    def _to_model(self, entity: User) -> UserModel:
        username = entity.username

        password_hash_value = (
            entity.password_hash.value
            if isinstance(entity.password_hash, HashedPasswordSHA256)
            else entity.password_hash
        )
        role_value = (
            entity.role.value if isinstance(entity.role, UserRole) else entity.role
        )

        model_kwargs = {
            "username": username,
            "hashed_password": password_hash_value,
            "role": role_value,
            "is_active": entity.is_active,
        }

        if entity.user_id:
            from uuid import UUID

            model_kwargs["user_id"] = UUID(entity.user_id)

        if entity.created_at:
            model_kwargs["created_at"] = entity.created_at
        if entity.updated_at:
            model_kwargs["updated_at"] = entity.updated_at

        return UserModel(**model_kwargs)

    async def _create(self, user: User) -> User:
        model = self._to_model(user)

        self._session.add(model)
        await self._session.flush()
        await self._session.refresh(model)  # Получаем сгенерированные поля
        await self._session.commit()

        return self._to_entity(model)

    async def _update(self, user: User) -> User:
        model = await self._session.get(UserModel, user.user_id)
        if model is None:
            raise ValueError(f"User with id {user.user_id} not found")

        model.username = user.username
        model.hashed_password = user.password_hash.value
        model.is_active = user.is_active
        model.role = user.role

        await self._session.flush()
        await self._session.refresh(model)
        await self._session.commit()

        return self._to_entity(model)

    async def save(self, user: User) -> User:
        if user.user_id is None:
            # Создание нового пользователя
            return await self._create(user)
        else:
            # Обновление существующего пользователя
            return await self._update(user)

    async def update(self, user: User) -> User:
        if user.user_id is None:
            raise ValueError("Cannot update user without ID")

        return await self._update(user)

    async def delete(self, user_id: str) -> bool:
        query = select(UserModel).where(UserModel.user_id == UUID(user_id))
        result = await self._session.execute(query)
        model = result.scalar_one_or_none()

        if model:
            await self._session.delete(model)
            await self._session.commit()
            return True

        return False

    async def get_by_id(self, user_id: str) -> User | None:
        """Возвращает пользователя по идентификатору.

        Args:
            user_id: Идентификатор пользователя в формате UUID (строка).

        Returns:
            Объект ``User`` или ``None``, если запись не найдена.
        """
        if isinstance(user_id, str):
            user_id = UUID(user_id)

        model = await self._session.get(UserModel, user_id)
        return self._to_entity(model) if model else None

    async def get_by_username(self, username: str) -> User | None:
        """Возвращает пользователя по имени пользователя.

        Args:
            username: Значение типа ``UserName``.

        Returns:
            Объект ``User`` или ``None``, если запись не найдена.
        """
        query = select(UserModel).where(UserModel.username == username)
        result = await self._session.execute(query)
        model = result.scalar_one_or_none()

        return self._to_entity(model) if model else None

    async def exists_with_username(self, username: str) -> bool:
        user = await self.get_by_username(username=username)
        return user is not None

    async def get_all(
        self,
        limit: int = 50,
        offset: int = 0,
        is_active: Optional[bool] = None,
        role: Optional[UserRole] = None,
    ) -> List[User]:
        base_query = select(UserModel)

        # Применяем фильтры
        conditions = []

        if is_active is not None:
            conditions.append(UserModel.is_active == is_active)

        if role is not None:
            conditions.append(UserModel.role == role)

        if conditions:
            base_query = base_query.where(and_(*conditions))

        # Запрос для получения общего количества (без пагинации)
        count_query = select(func.count()).select_from(UserModel)
        if conditions:
            count_query = count_query.where(and_(*conditions))

        # Выполняем запрос на количество
        count_result = await self._session.execute(count_query)
        total = count_result.scalar_one()

        # Запрос для получения данных с пагинацией
        data_query = base_query.offset(offset).limit(limit)

        # Выполняем запрос на данные
        result = await self._session.execute(data_query)
        models = result.scalars().all()

        # Преобразуем модели в сущности
        users = [self._to_entity(model) for model in models]

        return users, total
