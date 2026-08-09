"""
SentinelAPI - Attack Detection Patterns

Contains regex patterns used by the detection engine
to identify common malicious request payloads.
"""

import re


# ============================================================
# SQL Injection
# ============================================================

SQL_INJECTION_PATTERNS = [

    # UNION SELECT
    re.compile(
        r"\bUNION\b\s+(?:ALL\s+)?\bSELECT\b",
        re.IGNORECASE,
    ),

    # SELECT * FROM
    re.compile(
        r"\bSELECT\b\s+\*\s+\bFROM\b\s+[\w.`]+",
        re.IGNORECASE,
    ),

    # SELECT specific SQL fields FROM table
    # Requires SQL-like field names rather than natural language.
    re.compile(
        r"\bSELECT\b\s+(?:id|username|email|password|passwd|user_id|account_id)"
        r"(?:\s*,\s*(?:id|username|email|password|passwd|user_id|account_id))*"
        r"\s+\bFROM\b\s+[\w.`]+",
        re.IGNORECASE,
    ),

    # INSERT INTO
    re.compile(
        r"\bINSERT\b\s+\bINTO\b\s+[\w.]+",
        re.IGNORECASE,
    ),

    # UPDATE ... SET
    re.compile(
        r"\bUPDATE\b\s+[\w.]+\s+\bSET\b",
        re.IGNORECASE,
    ),

    # DELETE FROM
    re.compile(
        r"\bDELETE\b\s+\bFROM\b\s+[\w.]+",
        re.IGNORECASE,
    ),

    # DROP TABLE
    re.compile(
        r"\bDROP\b\s+\bTABLE\b\s+[\w.]+",
        re.IGNORECASE,
    ),

    # Numeric boolean injection
    # Examples:
    # 1=1
    # '1'='1'
    re.compile(
        r"""['"]?\s*\d+\s*['"]?\s*=\s*['"]?\s*\d+\s*['"]?""",
        re.IGNORECASE,
    ),

    # SQL comment
    re.compile(
        r"(?:--|#)\s*$",
        re.IGNORECASE,
    ),

    # Quoted OR injection
    # Example: ' OR '1'='1
    re.compile(
        r"""['"]\s*OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?""",
        re.IGNORECASE,
    ),
]


# ============================================================
# Cross-Site Scripting (XSS)
# ============================================================

XSS_PATTERNS = [

    # <script>...</script>
    re.compile(
        r"<script\b[^>]*>.*?</script\s*>",
        re.IGNORECASE | re.DOTALL,
    ),

    # javascript:
    re.compile(
        r"javascript\s*:",
        re.IGNORECASE,
    ),

    # Event handlers
    re.compile(
        r"\bonerror\s*=",
        re.IGNORECASE,
    ),

    re.compile(
        r"\bonload\s*=",
        re.IGNORECASE,
    ),

    re.compile(
        r"\bonclick\s*=",
        re.IGNORECASE,
    ),

    # iframe
    re.compile(
        r"<iframe\b",
        re.IGNORECASE,
    ),
]


# ============================================================
# Path Traversal
# ============================================================

PATH_TRAVERSAL_PATTERNS = [

    # ../
    re.compile(
        r"\.\./",
        re.IGNORECASE,
    ),

    # ..\
    re.compile(
        r"\.\.\\",
        re.IGNORECASE,
    ),

    # URL encoded ../
    re.compile(
        r"%2e%2e%2f",
        re.IGNORECASE,
    ),

    # URL encoded ..\
    re.compile(
        r"%2e%2e%5c",
        re.IGNORECASE,
    ),

    # Sensitive Unix files
    re.compile(
        r"/etc/passwd",
        re.IGNORECASE,
    ),

    re.compile(
        r"/etc/shadow",
        re.IGNORECASE,
    ),
]


# ============================================================
# Command Injection
# ============================================================

COMMAND_INJECTION_PATTERNS = [

    # ; command
    re.compile(
        r";\s*(?:cat|ls|pwd|whoami|id|uname|curl|wget)\b",
        re.IGNORECASE,
    ),

    # | command
    re.compile(
        r"\|\s*(?:cat|ls|pwd|whoami|id|uname|curl|wget)\b",
        re.IGNORECASE,
    ),

    # && command
    re.compile(
        r"&&\s*(?:cat|ls|pwd|whoami|id|uname|curl|wget)\b",
        re.IGNORECASE,
    ),

    # $(command)
    re.compile(
        r"\$\([^)]*\)",
        re.IGNORECASE,
    ),

    # `command`
    re.compile(
        r"`[^`]+`",
        re.IGNORECASE,
    ),
]


# ============================================================
# Authentication Abuse
# ============================================================

AUTHENTICATION_ABUSE_PATTERNS = [

    # Suspicious administrative credential references
    re.compile(
        r"(?:admin|root).*(?:password|passwd|login)",
        re.IGNORECASE,
    ),

    # Brute force / credential stuffing
    re.compile(
        r"(?:brute.?force|credential.?stuffing)",
        re.IGNORECASE,
    ),
]


# ============================================================
# Combined Pattern Registry
# ============================================================

ATTACK_PATTERNS = {
    "SQL_Injection": SQL_INJECTION_PATTERNS,
    "XSS": XSS_PATTERNS,
    "Path_Traversal": PATH_TRAVERSAL_PATTERNS,
    "Command_Injection": COMMAND_INJECTION_PATTERNS,
    "Authentication_Abuse": AUTHENTICATION_ABUSE_PATTERNS,
}


# ============================================================
# Detection Helper
# ============================================================

def detect_pattern(value: str) -> list[str]:
    """
    Scan a string against all registered attack patterns.

    Returns:
        List containing the names of detected attack types.
    """

    if not value:
        return []

    detected = []

    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(value):
                detected.append(attack_type)
                break

    return detected