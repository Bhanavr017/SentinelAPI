from sqlalchemy import select
from app.core.config import settings
from app.models.user import User
from app.services.database import AsyncSessionLocal


async def bootstrap_admin() -> None:
    if not settings.BOOTSTRAP_ADMIN_EMAIL:
        return

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(User.email == settings.BOOTSTRAP_ADMIN_EMAIL)
        )
        user = result.scalar_one_or_none()
        if user is None:
            return

        changed = False
        if not user.is_admin:
            user.is_admin = True
            changed = True
        if user.role != "admin":
            user.role = "admin"
            changed = True
        if changed:
            await db.commit()
