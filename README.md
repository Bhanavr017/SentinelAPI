cd ~/Documents/Project/SentinelAPI

cat > README.md <<'EOF'
# SentinelAPI

**Production-deployed API security gateway for automated abuse detection, risk-based prevention, authentication, and protected upstream API forwarding.**

SentinelAPI inspects incoming HTTP requests, normalizes and analyzes security-relevant request data, assigns a risk score, and automatically allows or blocks traffic before forwarding permitted requests to an upstream API.

It was built as a production-oriented evolution of an API abuse detection and prevention system, expanding the original detection capability into a complete security gateway with authentication, authorization, security telemetry, persistent event storage, and cloud deployment.

## Live Demo

**Production:**
https://sentinelapi-o9rl.onrender.com

**Swagger UI:**
https://sentinelapi-o9rl.onrender.com/docs

**OpenAPI:**
https://sentinelapi-o9rl.onrender.com/openapi.json

**JWKS:**
https://sentinelapi-o9rl.onrender.com/.well-known/jwks.json

**GitHub:**
https://github.com/Bhanavr017/SentinelAPI

## What SentinelAPI Does

SentinelAPI operates as an automated security layer between clients and an upstream API.

```text
                         Client
                           |
                           v
                 +-------------------+
                 |    SentinelAPI    |
                 |  Security Gateway  |
                 +---------+---------+
                           |
              +------------+-------------+
              |                          |
              v                          v
       Request Inspection          Rate Limiting
              |                          |
              +------------+-------------+
                           |
                           v
                  Detection Engine
                           |
              +------------+-------------+
              |                          |
              v                          v
       Attack Classification       Risk Scoring
              |                          |
              +------------+-------------+
                           |
                           v
                    Policy Decision
                    /             \
                   /               \
                BLOCK             ALLOW
                  |                  |
                  v                  v
          Security Event       Upstream API
          + PostgreSQL               |
                                     v
                              API Response

        Redis <---- Rate limits / temporary blocking
        PostgreSQL <- Persistent security events