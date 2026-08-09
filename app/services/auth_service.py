from app.core.security import (
    verify_password,
    create_access_token,
)

from app.models.user import User
from app.services.user_service import UserService


class AuthService:

    def __init__(self, user_service: UserService):
        self.user_service = user_service

    async def authenticate(self, identifier: str, password: str):
        user = await self.user_service.get_by_login_identifier(
            identifier
        )

        if user is None:
            return None

        if not verify_password(
            password,
            user.hashed_password,
        ):
            return None

        return user

    def create_token(self, user: User) -> str:
        return create_access_token(
            data={"sub": str(user.id)}
        )
