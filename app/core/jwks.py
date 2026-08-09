from cryptography.hazmat.primitives import serialization
from jose.utils import base64url_encode
from app.core.config import settings


def _int_to_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def get_jwks() -> dict:
    if settings.JWT_ALGORITHM.upper() != "RS256" or not settings.JWT_PRIVATE_KEY_B64:
        return {"keys": []}

    import base64
    private_key = serialization.load_pem_private_key(
        base64.b64decode(settings.JWT_PRIVATE_KEY_B64), password=None
    )
    numbers = private_key.public_key().public_numbers()

    return {"keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": settings.JWT_KID,
        "n": base64url_encode(_int_to_bytes(numbers.n)).decode(),
        "e": base64url_encode(_int_to_bytes(numbers.e)).decode(),
    }]}
