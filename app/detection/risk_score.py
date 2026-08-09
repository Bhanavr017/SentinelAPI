"""
SentinelAPI - Risk Scoring Engine

Converts detected attack categories into a numerical risk score.

Score range:
    0   -> No detected risk
    1-29 -> Low
    30-59 -> Medium
    60-79 -> High
    80-100 -> Critical
"""

from typing import Iterable


# ============================================================
# Risk Scores
# ============================================================

ATTACK_SCORES = {
    "SQL_Injection": 90,
    "Command_Injection": 95,
    "Path_Traversal": 80,
    "XSS": 70,
    "Authentication_Abuse": 75,
}


# ============================================================
# Risk Levels
# ============================================================

def get_risk_level(score: int) -> str:
    """
    Convert a numerical score into a risk classification.
    """

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "NONE"


# ============================================================
# Calculate Score
# ============================================================

def calculate_risk_score(
    detected_attacks: Iterable[str],
) -> int:
    """
    Calculate the risk score from detected attack types.

    When multiple attack types are detected, the highest
    individual score is used.

    The result is always limited to 100.
    """

    scores = [
        ATTACK_SCORES.get(attack, 0)
        for attack in detected_attacks
    ]

    if not scores:
        return 0

    return min(max(scores), 100)


# ============================================================
# Detailed Risk Result
# ============================================================

def analyze_risk(
    detected_attacks: Iterable[str],
) -> dict:
    """
    Return a complete risk analysis.

    Example:

        {
            "score": 90,
            "level": "CRITICAL",
            "attacks": ["SQL_Injection"]
        }
    """

    attacks = list(detected_attacks)

    score = calculate_risk_score(attacks)

    return {
        "score": score,
        "level": get_risk_level(score),
        "attacks": attacks,
    }