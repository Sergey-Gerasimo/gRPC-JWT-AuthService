from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel
from uuid import uuid4

from domain.values import HashedPasswordSHA256
from domain.enums import UserRole


class User(BaseModel):
    username: str
    password_hash: HashedPasswordSHA256
    role: UserRole = UserRole.USER
    is_active: bool = True
    user_id: Optional[str] = None
    updated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    @classmethod
    def create(
        cls,
        username: str,
        password_hash: HashedPasswordSHA256,
        role: UserRole = UserRole.USER,
    ) -> "User":
        return cls(
            username=username,
            password_hash=password_hash,
            role=role,
            is_active=True,
        )

    def change_username(self, new_username: str) -> None:
        self.username = new_username

    def change_password(self, new_password_hash: HashedPasswordSHA256) -> None:
        self.password_hash = new_password_hash

    def change_role(self, new_role: UserRole) -> None:
        self.role = new_role

    def activate(self) -> None:
        self.is_active = True

    def deactivate(self) -> None:
        self.is_active = False

    def authenticate(self, password_hash: HashedPasswordSHA256) -> bool:
        return self.password_hash == password_hash and self.is_active
