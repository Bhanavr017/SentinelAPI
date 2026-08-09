from datetime import datetime, timedelta, timezone
import base64
import secrets
import uuid

import bcrypt
from cryptography.hazmat.primitives import serialization
from jose import JWTError, jwt

from app.core.config import settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def _private_key():
    if not settings.JWT_PRIVATE_KEY_B64:
        raise RuntimeError(
            "JWT_PRIVATE_KEY_B64 is required when "
            "JWT_ALGORITHM=RS256"
        )

    raw = base64.b64decode(
        settings.JWT_PRIVATE_KEY_B64
    )

    return serialization.load_pem_private_key(
        raw,
        password=None,
    )


def _public_key():
    return _private_key().public_key()


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    now = datetime.now(timezone.utc)

    expire = now + (
        expires_delta
        or timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    payload = data.copy()

    # Every authentication token receives a unique
    # server-generated identifier.
    payload.setdefault(
        "jti",
        str(uuid.uuid4()),
    )

    payload.update(
        {
            "iat": int(now.timestamp()),
            "exp": expire,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
        }
    )

    if settings.JWT_ALGORITHM.upper() == "RS256":
        return jwt.encode(
            payload,
            _private_key(),
            algorithm="RS256",
            headers={
                "kid": settings.JWT_KID,
            },
        )

    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def verify_token(token: str):
    try:
        algorithm = settings.JWT_ALGORITHM.upper()

        if algorithm == "RS256":
            key = _public_key()
            algorithms = ["RS256"]
        else:
            key = settings.SECRET_KEY
            algorithms = [settings.JWT_ALGORITHM]

        payload = jwt.decode(
            token,
            key,
            algorithms=algorithms,
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )

        # SentinelAPI authentication tokens must contain
        # a unique server-generated JWT ID.
        if not payload.get("jti"):
            return None

        return payload

    except (
        JWTError,
        RuntimeError,
        ValueError,
    ):
        return None


def token_expiration_seconds(payload: dict) -> int:
    """
    Return the remaining lifetime of a JWT in seconds.

    Used when creating a Redis revocation entry so that
    revoked-token records disappear automatically after
    the original JWT would have expired.
    """
    exp = payload.get("exp")

    if exp is None:
        return 0

    try:
        remaining = int(
            float(exp)
            - datetime.now(timezone.utc).timestamp()
        )
    except (TypeError, ValueError):
        return 0

    return max(remaining, 0)


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)
