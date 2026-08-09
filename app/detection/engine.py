"""
SentinelAPI - Detection Engine

Combines:
    1. Attack pattern detection
    2. Risk scoring
    3. Risk classification

The engine does not handle HTTP requests directly.
It receives text and returns a structured detection result.
"""

from app.detection.patterns import detect_pattern
from app.detection.risk_score import analyze_risk


def analyze_request(value: str) -> dict:
    """
    Analyze a request value for known attack patterns.

    Returns:

        {
            "detected": True,
            "attacks": ["SQL_Injection"],
            "score": 90,
            "level": "CRITICAL"
        }

    For clean input:

        {
            "detected": False,
            "attacks": [],
            "score": 0,
            "level": "NONE"
        }
    """

    detected_attacks = detect_pattern(value)

    risk = analyze_risk(detected_attacks)

    return {
        "detected": bool(detected_attacks),
        "attacks": risk["attacks"],
        "score": risk["score"],
        "level": risk["level"],
    }