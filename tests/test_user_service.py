import pytest
import pytest_asyncio
import asyncpg
import grpc
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from datetime import datetime, timezone
from uuid import uuid4

from domain.values import HashedPasswordSHA256
from grpc_generated.auth_pb2 import (
    CreateUserRequest,
    AuthRequest,
    UserId,
    UsernameRequest,
    UpdateUserRequest,
)
from grpc_generated.auth_pb2_grpc import AuthServiceStub, UserServiceStub

from domain.enums import UserRole
from domain.entities import User
from repository.user_repository import UserRepository


@pytest.fixture
def user_service_stub(grpc_channel):
    return UserServiceStub(grpc_channel)


@pytest.fixture
def auth_service_stub(grpc_channel):
    return AuthServiceStub(grpc_channel)


def create_metadata_with_token(access_token: str):
    """Создает метаданные с токеном для gRPC запросов."""
    # Используем grpc.Metadata для правильной передачи метаданных
    return (("authorization", f"Bearer {access_token}"),)


@pytest.fixture
async def test_user(user_service_stub: UserServiceStub, test_user_admin_token: dict):

    metadata = create_metadata_with_token(test_user_admin_token["access_token"])
    response = user_service_stub.create_user(
        CreateUserRequest(username="testuser", password="testpassword"),
        metadata=metadata,
    )
    assert response.success, f"Failed to create user: {response.message}"

    return {
        "user_id": response.user.id,
        "username": "testuser",
        "password": "testpassword",
    }


@pytest_asyncio.fixture
async def test_admin_user() -> dict:
    """Создает тестового администратора через прямой SQL запрос."""
    # Параметры подключения к БД
    db_host = "localhost"
    db_port = 5432
    db_user = "user"
    db_password = "password"
    db_name = "auth_db"

    # Генерируем хэш пароля
    password_hash = HashedPasswordSHA256.from_plain_password("testpassword")

    # Генерируем UUID для пользователя
    user_id = uuid4()

    # Текущее время
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    conn = None
    try:
        conn = await asyncpg.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name,
            timeout=10,
            command_timeout=10,
        )

        # Вставляем пользователя напрямую через SQL
        await conn.execute(
            """
            INSERT INTO users (user_id, username, hashed_password, role, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            user_id,
            "testadmin",
            password_hash.value,
            UserRole.ADMIN.value,
            True,
            now,
            now,
        )

        # Получаем вставленную запись обратно
        row = await conn.fetchrow(
            """
            SELECT user_id, username, hashed_password, role, is_active, created_at, updated_at
            FROM users
            WHERE user_id = $1
            """,
            user_id,
        )

        # Создаем объект User из domain/entities/user.py
        saved_user = User(
            user_id=str(row["user_id"]),
            username=row["username"],
            password_hash=HashedPasswordSHA256(value=row["hashed_password"]),
            role=UserRole(row["role"]),
            is_active=row["is_active"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

        return {
            "user": saved_user,
            "username": "testadmin",
            "password": "testpassword",
        }
    finally:
        if conn:
            await conn.close()


@pytest.fixture
def test_user_admin_token(auth_service_stub: AuthServiceStub, test_admin_user: dict):
    response = auth_service_stub.authentication(
        AuthRequest(
            username=test_admin_user["username"], password=test_admin_user["password"]
        )
    )
    assert response.success, f"Failed to authenticate: {response.message}"

    return {
        "access_token": response.access_token.token,
        "refresh_token": response.refresh_token.token,
    }


class TestUserServiceSmoke:
    async def test_create_user(self, user_service_stub, test_user_admin_token: dict):
        metadata = create_metadata_with_token(test_user_admin_token["access_token"])
        response = user_service_stub.create_user(
            CreateUserRequest(username="testuser", password="testpassword"),
            metadata=metadata,
        )
        assert response.success, f"Failed to create user: {response.message}"
        assert response.user.username == "testuser", "Username is missing"
        assert response.user.role == UserRole.USER.value, "Role is missing"
        assert response.user.is_active, "User is not active"
        assert response.user.created_at, "Created at is missing"
        assert response.user.updated_at, "Updated at is missing"

    async def test_get_user(
        self, user_service_stub, test_user_admin_token: dict, test_user: dict
    ):
        metadata = create_metadata_with_token(test_user_admin_token["access_token"])
        response = user_service_stub.get_user(
            UserId(id=test_user["user_id"]),
            metadata=metadata,
        )
        assert response.success, "Response success should be True"
        assert response.user.username == test_user["username"], "Username is missing"
        assert response.user.role == UserRole.USER.value, "Role is missing"
        assert response.user.is_active, "User is not active"
        assert response.user.created_at, "Created at is missing"
        assert response.user.updated_at, "Updated at is missing"

    async def test_get_user_by_username(
        self, user_service_stub, test_user_admin_token: dict, test_user: dict
    ):
        metadata = create_metadata_with_token(test_user_admin_token["access_token"])
        response = user_service_stub.get_user_by_username(
            UsernameRequest(username=test_user["username"]),
            metadata=metadata,
        )
        assert response.success, "Response success should be True"
        assert response.user.username == test_user["username"], "Username is missing"
        assert response.user.role == UserRole.USER.value, "Role is missing"

    async def test_update_user(
        self, user_service_stub, test_user_admin_token: dict, test_user: dict
    ):
        metadata = create_metadata_with_token(test_user_admin_token["access_token"])
        response = user_service_stub.update_user(
            UpdateUserRequest(id=test_user["user_id"], username="testuser2"),
            metadata=metadata,
        )
        assert response.success, "Response success should be True"
        assert response.user.username == "testuser2", "Username is missing"
        assert response.user.role == UserRole.USER.value, "Role is missing"

    async def test_delete_user(
        self, user_service_stub, test_user_admin_token: dict, test_user: dict
    ):
        metadata = create_metadata_with_token(test_user_admin_token["access_token"])
        response = user_service_stub.delete_user(
            UserId(id=test_user["user_id"]),
            metadata=metadata,
        )
        assert response.success, "Response success should be True"
