from datetime import datetime, timezone
from uuid import UUID as PyUUID, uuid4
from sqlalchemy import String, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID as SAUUID
from sqlalchemy.orm import Mapped, mapped_column

from database import Base
from domain.enums import UserRole

get_current_time = lambda: datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[PyUUID] = mapped_column(
        SAUUID(as_uuid=True), default=uuid4, primary_key=True
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(SQLEnum(UserRole), default=UserRole.USER)
    created_at: Mapped[datetime] = mapped_column(default=get_current_time)
    updated_at: Mapped[datetime] = mapped_column(
        default=get_current_time, onupdate=get_current_time
    )
    is_active: Mapped[bool] = mapped_column(default=True)

    @property
    def is_admin(self):
        return self.role == UserRole.ADMIN
