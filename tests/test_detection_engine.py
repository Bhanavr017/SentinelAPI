from app.detection.engine import analyze_request


def test_clean_request():
    result = analyze_request(
        "GET /home HTTP/1.1 Host: example.com"
    )

    assert result["detected"] is False
    assert result["attacks"] == []
    assert result["score"] == 0
    assert result["level"] == "NONE"


def test_sql_injection_detection():
    result = analyze_request(
        "GET /login?id=1 UNION SELECT username FROM users"
    )

    assert result["detected"] is True
    assert "SQL_Injection" in result["attacks"]
    assert result["score"] == 90
    assert result["level"] == "CRITICAL"


def test_xss_detection():
    result = analyze_request(
        '<script>alert("XSS")</script>'
    )

    assert result["detected"] is True
    assert "XSS" in result["attacks"]
    assert result["score"] == 70
    assert result["level"] == "HIGH"


def test_path_traversal_detection():
    result = analyze_request(
        "GET /download?file=../../etc/passwd"
    )

    assert result["detected"] is True
    assert "Path_Traversal" in result["attacks"]
    assert result["score"] == 80
    assert result["level"] == "CRITICAL"


def test_command_injection_detection():
    result = analyze_request(
        "GET /ping?host=example.com; whoami"
    )

    assert result["detected"] is True
    assert "Command_Injection" in result["attacks"]
    assert result["score"] == 95
    assert result["level"] == "CRITICAL"


def test_authentication_abuse_detection():
    result = analyze_request(
        "POST /login admin password"
    )

    assert result["detected"] is True
    assert "Authentication_Abuse" in result["attacks"]
    assert result["score"] == 75
    assert result["level"] == "HIGH"
