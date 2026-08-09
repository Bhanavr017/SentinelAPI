import redis.asyncio as redis

from app.core.config import settings
from app.core.logger import logger


class RedisService:

    def __init__(self):
        self.client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True
        )

    async def connect(self):
        try:
            await self.client.ping()
            logger.info("Redis connected")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")

    async def close(self):
        await self.client.aclose()


redis_service = RedisService()