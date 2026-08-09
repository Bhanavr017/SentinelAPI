from typing import Iterable


ATTACK_SCORES = {
    "SQL_Injection": 90,
    "Command_Injection": 95,
    "Path_Traversal": 80,
    "XSS": 70,
    "Authentication_Abuse": 75,
}


def get_risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def calculate_risk_score(
    detected_attacks: Iterable[str],
) -> int:
    """
    Return the highest severity score among detected attacks.

    The highest-severity attack determines the request risk.
    Unknown attack types contribute a score of zero.
    """
    attacks = list(detected_attacks)

    if not attacks:
        return 0

    scores = [
        ATTACK_SCORES.get(attack, 0)
        for attack in attacks
    ]

    return max(scores)


def analyze_risk(
    detected_attacks: Iterable[str],
) -> dict:
    attacks = list(detected_attacks)
    score = calculate_risk_score(attacks)

    return {
        "score": score,
        "level": get_risk_level(score),
        "attacks": attacks,
    }
