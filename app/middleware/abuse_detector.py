"""
SentinelAPI - Abuse Detection Middleware

Responsibilities:

1. Inspect request path and query string.
2. Inspect request body when appropriate.
3. Detect malicious patterns.
4. Calculate risk.
5. Write detected attacks to the security log.
6. Persist detected attacks to the security_events database table.
7. Return HTTP 403 for high/critical attacks.

Authentication credentials are never inspected as generic payloads.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.detection.engine import analyze_request
from app.core.attack_logger import log_attack
from app.services.database import AsyncSessionLocal
from app.services.security_event_service import create_security_event


class AbuseDetectionMiddleware(BaseHTTPMiddleware):

    async def dispatch(
        self,
        request: Request,
        call_next,
    ):

        # ====================================================
        # 1. Request metadata
        # ====================================================

        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        method = request.method
        path = request.url.path
        query = request.url.query

        user_agent = request.headers.get(
            "user-agent",
            "unknown",
        )

        # ====================================================
        # 2. Authentication endpoints
        # ====================================================
        #
        # Never inspect passwords or authentication bodies.
        #
        # We still inspect the URL path/query so malicious
        # parameters cannot bypass the detection layer.
        # ====================================================

        authentication_paths = {
            "/auth/login",
            "/auth/register",
        }

        # ====================================================
        # 3. Build inspection values
        # ====================================================

        inspection_values = []

        # Always inspect path.
        inspection_values.append(path)

        # Inspect query string.
        if query:
            inspection_values.append(query)

        # Only inspect request bodies for non-auth endpoints.
        if path not in authentication_paths:

            body = b""

            try:
                body = await request.body()
            except Exception:
                body = b""

            if body:

                try:
                    body_text = body.decode(
                        "utf-8",
                        errors="ignore",
                    )

                    inspection_values.append(
                        body_text
                    )

                except Exception:
                    pass

        # ====================================================
        # 4. Run detection engine
        # ====================================================

        detected_attacks = []

        highest_score = 0
        highest_level = "NONE"

        for value in inspection_values:

            if not value:
                continue

            result = analyze_request(value)

            if not result["detected"]:
                continue

            for attack in result["attacks"]:

                if attack not in detected_attacks:
                    detected_attacks.append(attack)

            if result["score"] > highest_score:

                highest_score = result["score"]
                highest_level = result["level"]

        # ====================================================
        # 5. Handle detected attacks
        # ====================================================

        if detected_attacks:

            reason = ",".join(
                detected_attacks
            )

            # ------------------------------------------------
            # File-based attack logging
            # ------------------------------------------------

            try:

                log_attack(
                    ip_address=client_ip,
                    method=method,
                    path=path,
                    score=highest_score,
                    reason=reason,
                    user_agent=user_agent,
                )

            except Exception:
                # Logging failure must never disable protection.
                pass

            # ------------------------------------------------
            # Database security-event persistence
            # ------------------------------------------------

            try:

                async with AsyncSessionLocal() as db:

                    await create_security_event(
                        db=db,
                        ip_address=client_ip,
                        method=method,
                        path=path,
                        attack_type=reason,
                        risk_score=highest_score,
                        risk_level=highest_level,
                        user_agent=user_agent,
                    )

            except Exception:
                # Database logging failure must never disable
                # the actual attack blocking mechanism.
                pass

            # ------------------------------------------------
            # Block high/critical attacks
            # ------------------------------------------------

            if highest_score >= 60:

                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Malicious request detected",
                        "risk_score": highest_score,
                        "risk_level": highest_level,
                        "detected_attacks": detected_attacks,
                    },
                )

        # ====================================================
        # 6. Normal request
        # ====================================================

        return await call_next(request)
