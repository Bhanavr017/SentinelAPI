from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.schemas import (
    RegisterRequest,
    LoginResponse,
    UserResponse,
    MeResponse,
)

from app.services.database import get_db
from app.services.user_service import UserService
from app.services.auth_service import AuthService
from app.services.dependencies import get_current_user

from app.core.security import (
    hash_password,
    generate_api_key,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# ---------------------------------------------------------
# Register
# ---------------------------------------------------------

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):

    user_service = UserService(db)

    existing_username = await user_service.get_by_username(
        request.username
    )

    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    existing_email = await user_service.get_by_email(
        request.email
    )

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already exists",
        )

    user = User(
        username=request.username,
        email=request.email,
        hashed_password=hash_password(
            request.password
        ),
        api_key=generate_api_key(),
    )

    await user_service.create(user)

    return user


# ---------------------------------------------------------
# Login (OAuth2 Password Flow)
# ---------------------------------------------------------

@router.post(
    "/login",
    response_model=LoginResponse,
)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):

    user_service = UserService(db)
    auth_service = AuthService(user_service)

    user = await auth_service.authenticate(
        form_data.username,
        form_data.password,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    access_token = auth_service.create_token(
        user
    )

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
    )


# ---------------------------------------------------------
# Current Logged-in User
# ---------------------------------------------------------

@router.get(
    "/me",
    response_model=MeResponse,
)
async def get_me(
    current_user: User = Depends(get_current_user),
):

    return current_user