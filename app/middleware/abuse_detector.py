import uuid
from urllib.parse import unquote_plus

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.attack_logger import log_attack
from app.detection.engine import analyze_request
from app.services.database import AsyncSessionLocal
from app.services.redis_service import redis_service
from app.services.security_event_service import create_security_event


SECRET_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}


def normalized_variants(value: str) -> list[str]:
    """
    Generate a small set of URL-decoded variants for detection.

    The original value is always preserved. Additional variants are
    produced by repeatedly applying URL decoding, up to two times.
    """
    variants = [value]
    current = value

    for _ in range(2):
        decoded = unquote_plus(current)

        if decoded == current:
            break

        variants.append(decoded)
        current = decoded

    return variants


class AbuseDetectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        query = request.url.query
        user_agent = request.headers.get("user-agent", "unknown")

        authentication_paths = {
            "/auth/login",
            "/auth/register",
        }

        # ------------------------------------------------------------
        # Build individual request components for inspection
        # ------------------------------------------------------------

        values = [
            f"METHOD: {method}",
            f"PATH: {path}",
        ]

        if query:
            values.append(f"QUERY: {query}")

        for key, value in request.headers.items():
            if key.lower() not in SECRET_HEADERS:
                values.append(
                    f"HEADER {key}: {value}"
                )

        if path not in authentication_paths:
            try:
                body = await request.body()
            except Exception:
                body = b""

            if body:
                values.append(
                    "BODY: "
                    + body.decode(
                        "utf-8",
                        errors="ignore",
                    )
                )

        # ------------------------------------------------------------
        # Detection
        # ------------------------------------------------------------

        detected_attacks = []
        highest_score = 0
        highest_level = "NONE"

        # Inspect every HTTP component individually.
        inspection_values = list(values)

        # Also inspect the complete request as one searchable
        # representation. This is important for attack patterns
        # that span multiple request components.
        combined_request = "\n".join(values)

        if combined_request:
            inspection_values.append(
                combined_request
            )

        for value in inspection_values:
            for candidate in normalized_variants(value):
                result = analyze_request(candidate)

                if not result["detected"]:
                    continue

                for attack in result["attacks"]:
                    if attack not in detected_attacks:
                        detected_attacks.append(attack)

                if result["score"] > highest_score:
                    highest_score = result["score"]
                    highest_level = result["level"]

        # ------------------------------------------------------------
        # Security event detected
        # ------------------------------------------------------------

        if detected_attacks:
            reason = ",".join(detected_attacks)

            action = (
                "BLOCKED"
                if highest_score >= 60
                else "DETECTED"
            )

            # --------------------------------------------------------
            # Attack logger
            # --------------------------------------------------------

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
                pass

            # --------------------------------------------------------
            # Database security event
            # --------------------------------------------------------

            try:
                async with AsyncSessionLocal() as db:
                    await create_security_event(
                        db=db,
                        request_id=request_id,
                        ip_address=client_ip,
                        method=method,
                        path=path,
                        attack_type=reason,
                        risk_score=highest_score,
                        risk_level=highest_level,
                        action=action,
                        source="request_inspection",
                        user_agent=user_agent,
                    )
            except Exception:
                pass

            # --------------------------------------------------------
            # Redis metrics
            # --------------------------------------------------------

            try:
                await redis_service.client.incr(
                    "sentinel:metrics:detected"
                )

                if action == "BLOCKED":
                    await redis_service.client.incr(
                        "sentinel:metrics:blocked"
                    )
            except Exception:
                pass

            # --------------------------------------------------------
            # Block high-risk requests
            # --------------------------------------------------------

            if highest_score >= 60:
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Malicious request detected",
                        "request_id": request_id,
                        "risk_score": highest_score,
                        "risk_level": highest_level,
                        "detected_attacks": detected_attacks,
                        "action": "BLOCKED",
                    },
                    headers={
                        "X-Sentinel-Request-ID": request_id,
                        "X-Sentinel-Decision": "BLOCK",
                        "X-Sentinel-Risk-Score": str(
                            highest_score
                        ),
                    },
                )

        # ------------------------------------------------------------
        # Forward allowed request
        # ------------------------------------------------------------

        response = await call_next(request)

        # ------------------------------------------------------------
        # Allowed request metrics
        # ------------------------------------------------------------

        try:
            await redis_service.client.incr(
                "sentinel:metrics:allowed"
            )
        except Exception:
            pass

        # ------------------------------------------------------------
        # Sentinel response headers
        # ------------------------------------------------------------

        response.headers["X-Sentinel-Request-ID"] = request_id

        response.headers["X-Sentinel-Decision"] = (
            "DETECTED_ALLOW"
            if detected_attacks
            else "ALLOW"
        )

        response.headers["X-Sentinel-Risk-Score"] = str(
            highest_score
        )

        response.headers["X-Sentinel-Risk-Level"] = (
            highest_level
        )

        return response
