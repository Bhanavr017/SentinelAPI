from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


class UserService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_email(self, email: str):
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str):
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()

    async def get_by_login_identifier(self, identifier: str):
        result = await self.db.execute(
            select(User).where(
                or_(
                    User.username == identifier,
                    User.email == identifier,
                )
            )
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: int):
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def create(self, user: User):
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def update(self, user: User):
        await self.db.commit()
        await self.db.refresh(user)
        return user
