# SentinelAPI

SentinelAPI is a security-focused REST API built with FastAPI for detecting and blocking potentially malicious HTTP requests.

It combines HTTP request inspection, rule-based attack detection, risk scoring, Redis-backed rate limiting, temporary IP blocking, JWT authentication, role-based administration, and persistent security-event logging.

## Features

- FastAPI REST API
- JWT-based authentication
- bcrypt password hashing
- Role-based admin authorization
- SQL injection detection
- Cross-site scripting (XSS) detection
- Path traversal detection
- Command injection detection
- Authentication-abuse detection
- Risk scoring from 0 to 100
- Risk-level classification
- Automatic malicious-request blocking
- Redis-backed per-IP rate limiting
- Per-minute and per-hour request limits
- Temporary IP blocking after repeated violations
- Security-event logging
- Persistent security-event storage
- Admin security-event investigation
- Attack-type filtering
- Risk-level filtering
- IP-based investigation
- Security statistics
- OpenAPI documentation
- Automated pytest test suite

## Architecture

```text
                         HTTP Request
                              |
                              v
                    Request Logging Middleware
                              |
                              v
                       Redis Rate Limiter
                              |
                              v
                    Abuse Detection Middleware
                              |
                  +-----------+-----------+
                  |                       |
                  v                       v
          Normal Request          Suspicious Request
                  |                       |
                  v                       v
           Detection Engine        Risk Assessment
                  |                       |
                  v                       v
            Risk Scoring           Attack Detection
                  |                       |
                  v                       v
             API Response        Security Event Logging
                                          |
                                          v
                                   SQLite Database
                                          |
                                          v
                                    Admin API