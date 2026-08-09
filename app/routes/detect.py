from fastapi import APIRouter

from app.models.schemas import (
    DetectionRequest,
    DetectionResponse,
)

from app.services.detection_service import (
    analyze_detection_request,
)


router = APIRouter(
    prefix="",
    tags=["Detection"],
)


@router.post(
    "/detect",
    response_model=DetectionResponse,
)
async def detect(
    request: DetectionRequest,
) -> DetectionResponse:
    """
    Analyze an HTTP-style request for security threats.
    """

    result = analyze_detection_request(
        url=request.url,
        body=request.body,
        headers=request.headers,
    )

    detected = result.get(
        "detected",
        False,
    )

    attacks = result.get(
        "attacks",
        [],
    )

    score = result.get(
        "score",
        0,
    )

    level = result.get(
        "level",
        "NONE",
    )

    if detected:
        reason = (
            "Detected attack patterns: "
            + ", ".join(attacks)
        )
    else:
        reason = "No attack patterns detected"

    return DetectionResponse(
        detected=detected,
        attacks=attacks,
        score=score,
        level=level,
        blocked=False,
        reason=reason,
    )