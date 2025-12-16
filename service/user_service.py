from datetime import datetime
from logging import Logger, getLogger

from decorators import grpc_error_handler
from decorators.error_handler import ErrorResponseMixin
from domain.entities import User
from domain.enums import UserRole
from domain.values import HashedPasswordSHA256
from grpc_generated import auth_pb2, auth_pb2_grpc
from repository.user_repository import UserRepository

from domain.exceptions import (
    InvalidArgumentError,
    AlreadyExistsError,
    NotFoundError,
    ForbiddenError,
    TooManyAuthenticationAttemptsError,
    InvalidTokenError,
)


class UserService(auth_pb2_grpc.UserServiceServicer, ErrorResponseMixin):
    def __init__(self, user_repository: UserRepository, logger: Logger | None = None):
        self.user_repository = user_repository
        self.logger = logger or getLogger("UserService")
        super().__init__()

    def _to_proto_user(self, user: User) -> auth_pb2.User:
        return auth_pb2.User(
            username=user.username,
            role=auth_pb2.UserRole.Value(user.role.value),
            id=user.user_id or "",
            is_active=user.is_active,
            created_at=user.created_at.isoformat() if user.created_at else "",
            updated_at=user.updated_at.isoformat() if user.updated_at else "",
        )

    @grpc_error_handler(logger=getLogger("UserService"))
    async def create_user(self, request, context):
        if len(request.username) < 3:
            raise InvalidArgumentError("Username must be at least 3 characters long")
        if len(request.password) < 6:
            raise InvalidArgumentError("Password must be at least 6 characters long")

        exists = await self.user_repository.exists_with_username(request.username)
        if exists:
            raise AlreadyExistsError("User with this username already exists")

        password_hash = HashedPasswordSHA256.from_plain_password(request.password)
        if request.HasField("role"):
            # request.role is enum int (0,1,2). Map to domain enum by name.
            try:
                role_name = auth_pb2.UserRole.Name(request.role)
                role = UserRole(role_name)
            except ValueError:
                raise InvalidArgumentError("Invalid role value")
        else:
            role = UserRole.USER

        user = User.create(
            username=request.username,
            password_hash=password_hash,
            role=role,
        )
        user.is_active = request.is_active if request.HasField("is_active") else True

        saved = await self.user_repository.save(user)

        return auth_pb2.UserResponse(
            success=True,
            message="User created",
            timestamp=datetime.now().isoformat(),
            user=self._to_proto_user(saved),
        )

    @grpc_error_handler(logger=getLogger("UserService"))
    async def get_user(self, request, context):
        user = await self.user_repository.get_by_id(request.id)
        if not user:
            raise NotFoundError("User not found")
        return self._to_proto_user(user)

    @grpc_error_handler(logger=getLogger("UserService"))
    async def get_user_by_username(self, request, context):
        user = await self.user_repository.get_by_username(request.username)
        if not user:
            raise NotFoundError("User not found")
        return self._to_proto_user(user)

    @grpc_error_handler(logger=getLogger("UserService"))
    async def update_user(self, request, context):
        current = await self.user_repository.get_by_id(request.id)
        if not current:
            raise ForbiddenError("access denied")

        if request.HasField("username"):
            current.change_username(request.username)

        if request.HasField("password"):
            if len(request.password) < 6:
                raise InvalidArgumentError(
                    "Password must be at least 6 characters long"
                )
            new_hash = HashedPasswordSHA256.from_plain_password(request.password)
            current.change_password(new_hash)

        if request.HasField("role"):
            try:
                role_name = auth_pb2.UserRole.Name(request.role)
                current.role = UserRole(role_name)
            except ValueError:
                raise InvalidArgumentError("Invalid role value")

        if request.HasField("is_active"):
            current.is_active = request.is_active

        updated = await self.user_repository.update(current)

        return auth_pb2.UserResponse(
            success=True,
            message="User updated",
            timestamp=datetime.now().isoformat(),
            user=self._to_proto_user(updated),
        )

    @grpc_error_handler(logger=getLogger("UserService"))
    async def delete_user(self, request, context):
        deleted = await self.user_repository.delete(request.id)
        if not deleted:
            raise NotFoundError("User not found")
        return auth_pb2.SuccessResponse(
            success=True,
            message="User deleted",
            timestamp=datetime.now().isoformat(),
        )

    @grpc_error_handler(logger=getLogger("UserService"))
    async def list_users(self, request, context):
        role_filter = None
        if request.HasField("role"):
            try:
                role_name = auth_pb2.UserRole.Name(request.role)
                role_filter = UserRole(role_name)
            except ValueError:
                raise InvalidArgumentError("Invalid role value")

        is_active_filter = request.is_active if request.HasField("is_active") else None
        username_filter = request.username if request.HasField("username") else None

        # Pagination validation
        if request.limit < 0:
            raise InvalidArgumentError("Limit must be a positive integer.")
        if request.offset < 0:
            raise InvalidArgumentError("Offset must be a non-negative integer.")

        limit = request.limit or 50
        offset = request.offset or 0

        users, _ = await self.user_repository.get_all(
            limit=limit,
            offset=offset,
            is_active=is_active_filter,
            role=role_filter,
            username=username_filter,
        )

        return auth_pb2.UsersResponse(
            success=True,
            message="Users fetched",
            timestamp=datetime.now().isoformat(),
            users=[self._to_proto_user(u) for u in users],
        )
