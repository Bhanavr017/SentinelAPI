"""
SentinelAPI - Redis Rate Limiting Middleware

Provides:
- Per-IP sliding-window rate limiting
- Per-IP hourly protection
- Temporary blocking after repeated violations
- Redis-backed counters
- Graceful fail-open behavior if Redis is unavailable
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import settings
from app.services.redis_service import redis_service


class RateLimitMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        now = time.time()

        minute_key = f"sentinel:rate:minute:{client_ip}"
        hour_key = f"sentinel:rate:hour:{client_ip}"
        violation_key = f"sentinel:violations:{client_ip}"
        block_key = f"sentinel:block:{client_ip}"

        redis = redis_service.client

        try:
            # ------------------------------------------------
            # Check temporary block
            # ------------------------------------------------

            blocked = await redis.get(block_key)

            if blocked:
                ttl = await redis.ttl(block_key)

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Temporarily blocked due to repeated rate-limit violations",
                        "retry_after": max(ttl, 0),
                    },
                    headers={
                        "Retry-After": str(max(ttl, 0)),
                    },
                )

            # ------------------------------------------------
            # Minute sliding window
            # ------------------------------------------------

            minute_start = now - 60

            await redis.zremrangebyscore(
                minute_key,
                0,
                minute_start,
            )

            minute_count = await redis.zcard(minute_key)

            # ------------------------------------------------
            # Hour sliding window
            # ------------------------------------------------

            hour_start = now - 3600

            await redis.zremrangebyscore(
                hour_key,
                0,
                hour_start,
            )

            hour_count = await redis.zcard(hour_key)

            # ------------------------------------------------
            # Enforce limits
            # ------------------------------------------------

            minute_exceeded = (
                minute_count >= settings.RATE_LIMIT_PER_MINUTE
            )

            hour_exceeded = (
                hour_count >= settings.RATE_LIMIT_PER_HOUR
            )

            if minute_exceeded or hour_exceeded:

                violations = await redis.incr(
                    violation_key
                )

                await redis.expire(
                    violation_key,
                    settings.BLOCK_DURATION,
                )

                # --------------------------------------------
                # Automatic temporary block
                # --------------------------------------------

                if violations >= settings.BLOCK_THRESHOLD:

                    await redis.setex(
                        block_key,
                        settings.BLOCK_DURATION,
                        "1",
                    )

                    return JSONResponse(
                        status_code=429,
                        content={
                            "detail": "Temporarily blocked due to repeated rate-limit violations",
                            "retry_after": settings.BLOCK_DURATION,
                        },
                        headers={
                            "Retry-After": str(
                                settings.BLOCK_DURATION
                            ),
                        },
                    )

                retry_after = 60

                if hour_exceeded:
                    retry_after = 3600

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded",
                        "retry_after": retry_after,
                        "violations": violations,
                    },
                    headers={
                        "Retry-After": str(retry_after),
                    },
                )

            # ------------------------------------------------
            # Record request
            # ------------------------------------------------

            request_id = f"{now:.6f}"

            await redis.zadd(
                minute_key,
                {request_id: now},
            )

            await redis.expire(
                minute_key,
                60,
            )

            await redis.zadd(
                hour_key,
                {request_id: now},
            )

            await redis.expire(
                hour_key,
                3600,
            )

            # Successful request clears old violations.
            await redis.delete(violation_key)

            response = await call_next(request)

            # ------------------------------------------------
            # Rate-limit headers
            # ------------------------------------------------

            response.headers["X-RateLimit-Limit-Minute"] = str(
                settings.RATE_LIMIT_PER_MINUTE
            )

            response.headers["X-RateLimit-Remaining-Minute"] = str(
                max(
                    settings.RATE_LIMIT_PER_MINUTE
                    - minute_count
                    - 1,
                    0,
                )
            )

            return response

        except Exception:
            # -----------------------------------------------
            # Fail open if Redis is temporarily unavailable.
            #
            # Detection and authentication must continue
            # working even if Redis has a transient failure.
            # -----------------------------------------------

            return await call_next(request)
