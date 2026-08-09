"""
SentinelAPI - HTTP Request Logger Middleware

Logs basic HTTP request/response metadata without logging
passwords, authorization tokens, or request bodies.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logger import logger


class RequestLoggingMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        started = time.perf_counter()

        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        method = request.method
        path = request.url.path

        try:
            response = await call_next(request)

            duration_ms = (
                time.perf_counter() - started
            ) * 1000

            logger.info(
                "HTTP_REQUEST | "
                f"IP={client_ip} | "
                f"METHOD={method} | "
                f"PATH={path} | "
                f"STATUS={response.status_code} | "
                f"DURATION_MS={duration_ms:.2f}"
            )

            return response

        except Exception:
            duration_ms = (
                time.perf_counter() - started
            ) * 1000

            logger.exception(
                "HTTP_REQUEST_ERROR | "
                f"IP={client_ip} | "
                f"METHOD={method} | "
                f"PATH={path} | "
                f"DURATION_MS={duration_ms:.2f}"
            )

            raise
