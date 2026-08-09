from fastapi import APIRouter
from app.core.jwks import get_jwks

router = APIRouter(tags=["Authentication"])


@router.get("/.well-known/jwks.json")
async def jwks():
    return get_jwks()
