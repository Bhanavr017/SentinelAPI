from app.detection.risk_score import (
    analyze_risk,
    calculate_risk_score,
    get_risk_level,
)


def test_empty_risk():
    assert calculate_risk_score([]) == 0
    assert get_risk_level(0) == "NONE"


def test_risk_levels():
    assert get_risk_level(10) == "LOW"
    assert get_risk_level(30) == "MEDIUM"
    assert get_risk_level(60) == "HIGH"
    assert get_risk_level(80) == "CRITICAL"


def test_highest_attack_score_wins():
    score = calculate_risk_score(
        ["XSS", "SQL_Injection", "Path_Traversal"]
    )

    assert score == 90


def test_risk_analysis():
    result = analyze_risk(
        ["Command_Injection"]
    )

    assert result == {
        "score": 95,
        "level": "CRITICAL",
        "attacks": ["Command_Injection"],
    }
