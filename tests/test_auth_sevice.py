import pytest
import grpc
from grpc_generated.auth_pb2 import (
    AuthRequest,
    Token,
    ChangePasswordRequest,
)


@pytest.fixture
def test_user(auth_service_stub, cleanup_database):
    """Создает тестового пользователя через регистрацию."""
    user = {
        "username": "testuser",
        "password": "testpassword",
    }
    # Регистрируем пользователя
    response = auth_service_stub.registrate(
        AuthRequest(username=user["username"], password=user["password"])
    )
    assert response.success, f"Failed to register user: {response.message}"
    return user


@pytest.fixture
def authenticated_tokens(auth_service_stub, test_user):
    """Получает токены для аутентифицированного пользователя."""
    response = auth_service_stub.authentication(
        AuthRequest(username=test_user["username"], password=test_user["password"])
    )
    assert response.success, f"Failed to authenticate: {response.message}"
    return {
        "access_token": response.access_token.token,
        "refresh_token": response.refresh_token.token,
    }


def create_metadata_with_token(access_token: str):
    """Создает метаданные с токеном для gRPC запросов."""
    # Используем grpc.Metadata для правильной передачи метаданных
    return (("authorization", f"Bearer {access_token}"),)


class TestAuthServiceSmoke:
    async def test_registration(self, auth_service_stub, cleanup_database):
        """Тест регистрации нового пользователя."""
        request = AuthRequest(username="testuser_01", password="testpassword_01")
        response = auth_service_stub.registrate(request)
        assert response.success, f"Registration failed: {response.message}"

    async def test_authentication(self, auth_service_stub, cleanup_database, test_user):
        """Тест аутентификации пользователя."""
        request = AuthRequest(
            username=test_user["username"], password=test_user["password"]
        )
        response = auth_service_stub.authentication(request)
        assert response.success, f"Authentication failed: {response.message}"
        assert response.access_token.token, "Access token is missing"
        assert response.refresh_token.token, "Refresh token is missing"

    async def test_logout(
        self, auth_service_stub, cleanup_database, authenticated_tokens
    ):
        """Тест выхода из системы (требует авторизацию)."""
        request = Token(token=authenticated_tokens["access_token"])
        # Передаем токен через метаданные для авторизации
        metadata = create_metadata_with_token(authenticated_tokens["access_token"])
        response = auth_service_stub.logout(request, metadata=metadata, timeout=5)
        assert response.success, f"Logout failed: {response.message}"

    def test_refresh_token(self, auth_service_stub, authenticated_tokens):
        """Тест обновления токена."""
        request = Token(token=authenticated_tokens["refresh_token"])
        response = auth_service_stub.refresh_token(request)
        assert response.success, f"Refresh token failed: {response.message}"
        assert response.access_token.token, "New access token is missing"
        assert response.refresh_token.token, "New refresh token is missing"

    def test_get_user(self, auth_service_stub, authenticated_tokens):
        """Тест получения информации о пользователе (требует авторизацию)."""
        request = Token(token=authenticated_tokens["access_token"])
        # Передаем токен через метаданные для авторизации
        metadata = create_metadata_with_token(authenticated_tokens["access_token"])
        response = auth_service_stub.get_user(request, metadata=metadata)
        assert response.username, "Username is missing"
        assert response.id, "User ID is missing"

    def test_verify(self, auth_service_stub, authenticated_tokens):
        """Тест верификации токена."""
        request = Token(token=authenticated_tokens["access_token"])
        response = auth_service_stub.verify(request)
        assert response.success, f"Verify failed: {response.message}"

    def test_change_password(self, auth_service_stub, test_user, authenticated_tokens):
        """Тест смены пароля (требует авторизацию)."""
        request = ChangePasswordRequest(
            current_password=test_user["password"],
            new_password="newtestpassword",
            token=Token(token=authenticated_tokens["access_token"]),
        )
        # Передаем токен через метаданные для авторизации
        metadata = create_metadata_with_token(authenticated_tokens["access_token"])
        response = auth_service_stub.change_password(request, metadata=metadata)
        assert response.success, f"Change password failed: {response.message}"

        # Проверяем, что новый пароль работает
        new_auth_response = auth_service_stub.authentication(
            AuthRequest(username=test_user["username"], password="newtestpassword")
        )
        assert new_auth_response.success, "New password doesn't work"
