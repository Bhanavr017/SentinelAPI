from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.core.logger import logger

from app.services.database import init_db
from app.services.redis_service import redis_service
from app.services.admin_bootstrap import bootstrap_admin

# ----------------------------------------------------
# Import database models
# ----------------------------------------------------

from app.models.user import User
from app.models.security_event import SecurityEvent

# ----------------------------------------------------
# Middleware
# ----------------------------------------------------

from app.middleware.abuse_detector import (
    AbuseDetectionMiddleware,
)
from app.middleware.rate_limiter import (
    RateLimitMiddleware,
)
from app.middleware.request_logger import (
    RequestLoggingMiddleware,
)

# ----------------------------------------------------
# Routers
# ----------------------------------------------------

from app.routes.auth import router as auth_router
from app.routes.detect import router as detect_router
from app.routes.admin import router as admin_router
from app.routes.gateway import router as gateway_router
from app.routes.jwks import router as jwks_router
from app.routes.demo import router as demo_router

# ----------------------------------------------------
# Lifespan
# ----------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info(
        "Starting SentinelAPI..."
    )

    # ------------------------------------------------
    # Connect Redis
    # ------------------------------------------------

    await redis_service.connect()

    # ------------------------------------------------
    # Initialize database
    # ------------------------------------------------

    await init_db()
    await bootstrap_admin()

    logger.info(
        "Database initialized"
    )

    yield

    # ------------------------------------------------
    # Shutdown
    # ------------------------------------------------

    await redis_service.close()

    logger.info(
        "SentinelAPI stopped"
    )


# ----------------------------------------------------
# FastAPI Application
# ----------------------------------------------------

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
)

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)


# ----------------------------------------------------
# CORS
# ----------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------
# Abuse Detection Middleware
# ----------------------------------------------------

app.add_middleware(
    AbuseDetectionMiddleware
)

app.add_middleware(
    RateLimitMiddleware
)

app.add_middleware(
    RequestLoggingMiddleware
)

# ----------------------------------------------------
# Routers
# ----------------------------------------------------

app.include_router(auth_router)

app.include_router(detect_router)

app.include_router(admin_router)
app.include_router(gateway_router)
app.include_router(jwks_router)
app.include_router(demo_router)

# ----------------------------------------------------
# Root
# ----------------------------------------------------


@app.get(
    "/",
    tags=["System"],
    include_in_schema=False,
)
async def root():
    return FileResponse(
        "app/templates/index.html"
    )


# ----------------------------------------------------
# Health Check
# ----------------------------------------------------


@app.get(
    "/health",
    tags=["System"],
)
async def health():

    return {
        "status": "healthy",
        "redis": "connected",
        "database": "connected",
    }