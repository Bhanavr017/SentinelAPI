from datetime import datetime, UTC
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from app.services.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    api_key = Column(String(128), unique=True, nullable=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    role = Column(String(20), default="user", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None))
