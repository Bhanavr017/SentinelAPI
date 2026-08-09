# SentinelAPI

SentinelAPI is a FastAPI-based API security gateway that automatically inspects incoming HTTP traffic before it reaches protected API routes or an upstream service.

## Security capabilities

- Automatic request interception
- Method/path/query/body/header inspection
- URL-decoding normalization
- SQL injection detection
- XSS detection
- Path traversal detection
- Command injection detection
- Authentication-abuse detection
- 0-100 risk scoring
- Automatic high/critical blocking
- Redis-backed rate limiting and temporary IP blocking
- Persistent PostgreSQL security events
- Request IDs and security decision headers
- Reverse proxy under `/gateway/*`
- JWT authentication with username-or-email login
- RS256 JWT signing with key IDs and public JWKS endpoint
- Role-based admin authorization
- Admin event investigation and statistics
- SOC-style dashboard
- OpenAPI / Swagger
- Automated pytest regression tests
- Render deployment

## Request flow

```text
Client -> SentinelAPI Gateway -> Request Inspection
                                  |-- malicious -> 403 + event
                                  |-- safe -----> Upstream API
```

## Live gateway demo

```bash
curl -i "https://YOUR-SENTINEL-URL/gateway/anything?demo=hello"
curl -i "https://YOUR-SENTINEL-URL/gateway/anything?id=1%27%20OR%20%271%27%3D%271"
```

The malicious request should be rejected before forwarding.

## JWKS

Configure `JWT_PRIVATE_KEY_B64`, `JWT_KID`, `JWT_ISSUER`, and `JWT_AUDIENCE` in Render. `JWT_ALGORITHM=RS256` is set by the deployment blueprint. Public keys are exposed at `/.well-known/jwks.json`.

## Admin bootstrap

Configure `BOOTSTRAP_ADMIN_EMAIL=admin@example.com`. The startup migration promotes that existing account to `role=admin` and `is_admin=true`, so Render Shell is not required.

## Validation

```bash
source .venv/bin/activate
python -m compileall -q app
python -m pytest -q
python -m pytest -q tests/test_gateway.py

git diff --check
```
