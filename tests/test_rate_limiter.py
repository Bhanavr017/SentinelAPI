import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings


class FakeRedis:
    def __init__(self):
        self.data = {}
        self.zsets = {}
        self.expirations = {}

    async def ping(self):
        return True

    async def aclose(self):
        return None

    async def get(self, key):
        return self.data.get(key)

    async def setex(self, key, ttl, value):
        self.data[key] = value

    async def delete(self, key):
        self.data.pop(key, None)

    async def incr(self, key):
        self.data[key] = int(self.data.get(key, 0)) + 1
        return self.data[key]

    async def expire(self, key, ttl):
        self.expirations[key] = ttl

    async def ttl(self, key):
        return self.expirations.get(key, -1)

    async def zremrangebyscore(self, key, minimum, maximum):
        self.zsets.setdefault(key, {})

    async def zcard(self, key):
        return len(self.zsets.setdefault(key, {}))

    async def zadd(self, key, values):
        self.zsets.setdefault(key, {}).update(values)


def test_rate_limit_blocks_after_threshold(monkeypatch):
    fake = FakeRedis()

    monkeypatch.setattr(
        "app.middleware.rate_limiter.redis_service.client",
        fake,
    )

    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 0)
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_HOUR", 0)
    monkeypatch.setattr(settings, "BLOCK_THRESHOLD", 2)
    monkeypatch.setattr(settings, "BLOCK_DURATION", 3600)

    with TestClient(app) as client:
        first = client.get("/protected/echo")
        second = client.get("/protected/echo")
        third = client.get("/protected/echo")

    assert first.status_code == 429
    assert second.status_code == 429
    assert third.status_code == 429

    assert "retry_after" in third.json()


def test_rate_limit_headers_on_allowed_request(monkeypatch):
    fake = FakeRedis()

    monkeypatch.setattr(
        "app.middleware.rate_limiter.redis_service.client",
        fake,
    )

    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 60)
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_HOUR", 1000)

    with TestClient(app) as client:
        response = client.get("/protected/echo?demo=ratelimit")

    assert response.status_code == 200
    assert "X-RateLimit-Limit-Minute" in response.headers
    assert "X-RateLimit-Remaining-Minute" in response.headers
