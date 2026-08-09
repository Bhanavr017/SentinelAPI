import asyncio
import base64
import uuid
from datetime import timedelta

import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
    verify_token,
)
from app.main import app
from app.models.user import User
from app.services.database import AsyncSessionLocal


# ============================================================
# TEST HELPERS
# ============================================================

def _rsa_private_key_b64():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    return base64.b64encode(pem).decode()


def _unique_credentials():
    username = (
        "security_test_"
        + uuid.uuid4().hex[:10]
    )

    email = username + "@example.com"

    password = "SecurityTest_2026!"

    return username, email, password


async def _promote_user_to_admin(username: str):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(
                User.username == username
            )
        )

        user = result.scalar_one()

        user.is_admin = True
        user.role = "admin"

        await db.commit()


# ============================================================
# PASSWORD SECURITY
# ============================================================

def test_bcrypt_hash_round_trip_without_legacy_dependency():
    password = "SentinelTest123!"

    hashed = hash_password(password)

    assert hashed.startswith("$2")
    assert verify_password(password, hashed)
    assert not verify_password(
        "WrongPassword!",
        hashed,
    )

    assert bcrypt.checkpw(
        password.encode(),
        hashed.encode(),
    )


# ============================================================
# JWT SECURITY
# ============================================================

def test_rs256_jwt_and_claim_validation(monkeypatch):
    monkeypatch.setattr(
        settings,
        "JWT_ALGORITHM",
        "RS256",
    )

    monkeypatch.setattr(
        settings,
        "JWT_PRIVATE_KEY_B64",
        _rsa_private_key_b64(),
    )

    token = create_access_token(
        {"sub": "123"}
    )

    payload = verify_token(token)

    assert payload is not None
    assert payload["sub"] == "123"
    assert payload["iss"] == settings.JWT_ISSUER
    assert payload["aud"] == settings.JWT_AUDIENCE

    # Every access token must have a unique
    # server-generated JWT identifier.
    assert payload["jti"]
    assert isinstance(
        payload["jti"],
        str,
    )


def test_expired_rs256_token_is_rejected(monkeypatch):
    monkeypatch.setattr(
        settings,
        "JWT_ALGORITHM",
        "RS256",
    )

    monkeypatch.setattr(
        settings,
        "JWT_PRIVATE_KEY_B64",
        _rsa_private_key_b64(),
    )

    token = create_access_token(
        {"sub": "123"},
        expires_delta=timedelta(
            seconds=-1
        ),
    )

    assert verify_token(token) is None


def test_jwt_tokens_receive_unique_jti():
    token_one = create_access_token(
        {"sub": "123"}
    )

    token_two = create_access_token(
        {"sub": "123"}
    )

    payload_one = verify_token(token_one)
    payload_two = verify_token(token_two)

    assert payload_one is not None
    assert payload_two is not None

    assert payload_one["jti"]
    assert payload_two["jti"]

    assert (
        payload_one["jti"]
        != payload_two["jti"]
    )


# ============================================================
# JWKS
# ============================================================

def test_jwks_exposes_rsa_key_when_rs256_enabled(
    monkeypatch,
):
    monkeypatch.setattr(
        settings,
        "JWT_ALGORITHM",
        "RS256",
    )

    monkeypatch.setattr(
        settings,
        "JWT_PRIVATE_KEY_B64",
        _rsa_private_key_b64(),
    )

    with TestClient(app) as client:
        response = client.get(
            "/.well-known/jwks.json"
        )

    assert response.status_code == 200

    data = response.json()

    assert len(data["keys"]) == 1

    assert data["keys"][0]["kty"] == "RSA"
    assert data["keys"][0]["alg"] == "RS256"
    assert data["keys"][0]["kid"] == settings.JWT_KID

    assert data["keys"][0]["n"]
    assert data["keys"][0]["e"]


# ============================================================
# SESSION REVOCATION
# ============================================================

def test_logout_revokes_current_jwt():
    username, email, password = (
        _unique_credentials()
    )

    with TestClient(app) as client:

        # ----------------------------------------------------
        # Register
        # ----------------------------------------------------

        register = client.post(
            "/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password,
            },
        )

        assert register.status_code == 201, (
            register.text
        )

        # ----------------------------------------------------
        # Login
        # ----------------------------------------------------

        login = client.post(
            "/auth/login",
            data={
                "username": username,
                "password": password,
            },
        )

        assert login.status_code == 200, (
            login.text
        )

        token = login.json()["access_token"]

        assert token

        headers = {
            "Authorization": f"Bearer {token}"
        }

        # ----------------------------------------------------
        # Token works before logout
        # ----------------------------------------------------

        before_logout = client.get(
            "/auth/me",
            headers=headers,
        )

        assert before_logout.status_code == 200, (
            before_logout.text
        )

        # ----------------------------------------------------
        # Logout
        # ----------------------------------------------------

        logout = client.post(
            "/auth/logout",
            headers=headers,
        )

        assert logout.status_code == 204, (
            logout.text
        )

        # ----------------------------------------------------
        # Same JWT must now be rejected
        # ----------------------------------------------------

        after_logout = client.get(
            "/auth/me",
            headers=headers,
        )

        assert after_logout.status_code == 401
        assert after_logout.json()["detail"] == (
            "Session has been revoked"
        )


# ============================================================
# ADMIN SESSION REVOCATION
# ============================================================

def test_logout_revokes_admin_jwt():
    username, email, password = (
        _unique_credentials()
    )

    with TestClient(app) as client:

        # ----------------------------------------------------
        # Register isolated test account
        # ----------------------------------------------------

        register = client.post(
            "/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password,
            },
        )

        assert register.status_code == 201, (
            register.text
        )

        # ----------------------------------------------------
        # Promote only this test account
        # ----------------------------------------------------

        asyncio.run(
            _promote_user_to_admin(username)
        )

        # ----------------------------------------------------
        # Login as admin
        # ----------------------------------------------------

        login = client.post(
            "/auth/login",
            data={
                "username": username,
                "password": password,
            },
        )

        assert login.status_code == 200, (
            login.text
        )

        token = login.json()["access_token"]

        assert token

        headers = {
            "Authorization": f"Bearer {token}"
        }

        # ----------------------------------------------------
        # Admin access works before logout
        # ----------------------------------------------------

        before_logout = client.get(
            "/admin/stats",
            headers=headers,
        )

        assert before_logout.status_code == 200, (
            before_logout.text
        )

        # ----------------------------------------------------
        # Logout
        # ----------------------------------------------------

        logout = client.post(
            "/auth/logout",
            headers=headers,
        )

        assert logout.status_code == 204, (
            logout.text
        )

        # ----------------------------------------------------
        # Replaying the same admin JWT must fail
        # ----------------------------------------------------

        replay = client.get(
            "/admin/stats",
            headers=headers,
        )

        assert replay.status_code == 401
        assert replay.json()["detail"] == (
            "Session has been revoked"
        )


# ============================================================
# RBAC REGRESSION
# ============================================================

def test_normal_user_cannot_access_admin_api():
    username, email, password = (
        _unique_credentials()
    )

    with TestClient(app) as client:

        register = client.post(
            "/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password,
            },
        )

        assert register.status_code == 201, (
            register.text
        )

        login = client.post(
            "/auth/login",
            data={
                "username": username,
                "password": password,
            },
        )

        assert login.status_code == 200, (
            login.text
        )

        token = login.json()["access_token"]

        response = client.get(
            "/admin/stats",
            headers={
                "Authorization": f"Bearer {token}"
            },
        )

        assert response.status_code == 403
        assert response.json()["detail"] == (
            "Administrator privileges required"
        )
