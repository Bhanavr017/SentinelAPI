"""
SentinelAPI - Security Administration Routes

Admin-only endpoints for security-event monitoring,
filtering, statistics, and IP investigation.
"""

from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_event import SecurityEvent
from app.models.user import User
from app.services.database import get_db
from app.services.dependencies import get_current_admin
from app.services.redis_service import redis_service


router = APIRouter(
    prefix="/admin",
    tags=["Security Administration"],
)


# ============================================================
# Helpers
# ============================================================

def serialize_event(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "request_id": event.request_id,
        "ip_address": event.ip_address,
        "method": event.method,
        "path": event.path,
        "attack_type": event.attack_type,
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "action": event.action,
        "source": event.source,
        "user_agent": event.user_agent,
        "created_at": (
            event.created_at.isoformat()
            if event.created_at
            else None
        ),
    }


# ============================================================
# GET ATTACK EVENTS
# ============================================================

@router.get("/attacks")
async def get_attack_events(
    page: int = Query(
        default=1,
        ge=1,
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    attack_type: str | None = Query(
        default=None,
    ),
    risk_level: str | None = Query(
        default=None,
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    filters = []

    if attack_type:
        filters.append(
            SecurityEvent.attack_type == attack_type
        )

    if risk_level:
        filters.append(
            SecurityEvent.risk_level == risk_level.upper()
        )

    # --------------------------------------------------------
    # Total matching events
    # --------------------------------------------------------

    count_query = select(
        func.count(SecurityEvent.id)
    )

    if filters:
        count_query = count_query.where(*filters)

    count_result = await db.execute(count_query)

    total = count_result.scalar_one()

    # --------------------------------------------------------
    # Paginated events
    # --------------------------------------------------------

    offset = (page - 1) * limit

    events_query = (
        select(SecurityEvent)
        .order_by(
            desc(SecurityEvent.created_at)
        )
        .offset(offset)
        .limit(limit)
    )

    if filters:
        events_query = events_query.where(*filters)

    events_result = await db.execute(
        events_query
    )

    events = events_result.scalars().all()

    total_pages = (
        (total + limit - 1) // limit
        if total
        else 0
    )

    return {
        "page": page,
        "limit": limit,
        "count": len(events),
        "total": total,
        "total_pages": total_pages,
        "filters": {
            "attack_type": attack_type,
            "risk_level": (
                risk_level.upper()
                if risk_level
                else None
            ),
        },
        "events": [
            serialize_event(event)
            for event in events
        ],
    }


# ============================================================
# GET SINGLE ATTACK EVENT
# ============================================================

@router.get("/attacks/{event_id}")
async def get_attack_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(SecurityEvent).where(
            SecurityEvent.id == event_id
        )
    )

    event = result.scalar_one_or_none()

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Security event not found",
        )

    return serialize_event(event)


# ============================================================
# SECURITY STATISTICS
# ============================================================

@router.get("/stats")
async def get_security_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    # --------------------------------------------------------
    # Total events
    # --------------------------------------------------------

    total_result = await db.execute(
        select(
            func.count(SecurityEvent.id)
        )
    )

    total_events = total_result.scalar_one()

    # --------------------------------------------------------
    # Risk-level distribution
    # --------------------------------------------------------

    level_result = await db.execute(
        select(
            SecurityEvent.risk_level,
            func.count(SecurityEvent.id),
        )
        .group_by(
            SecurityEvent.risk_level
        )
    )

    risk_levels = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for level, count in level_result.all():

        if level:
            risk_levels[level.upper()] = count

    # --------------------------------------------------------
    # Attack-type distribution
    # --------------------------------------------------------

    attack_result = await db.execute(
        select(
            SecurityEvent.attack_type,
            func.count(SecurityEvent.id),
        )
        .group_by(
            SecurityEvent.attack_type
        )
        .order_by(
            desc(func.count(SecurityEvent.id))
        )
    )

    attack_types = {
        attack_type: count
        for attack_type, count
        in attack_result.all()
    }

    # --------------------------------------------------------
    # Average risk score
    # --------------------------------------------------------

    average_result = await db.execute(
        select(
            func.avg(SecurityEvent.risk_score)
        )
    )

    average_score = average_result.scalar_one()

    if average_score is not None:
        average_score = round(
            float(average_score),
            2,
        )
    else:
        average_score = 0

    # --------------------------------------------------------
    # Recent events
    # --------------------------------------------------------

    recent_result = await db.execute(
        select(SecurityEvent)
        .order_by(
            desc(SecurityEvent.created_at)
        )
        .limit(10)
    )

    recent_events = recent_result.scalars().all()

    blocked_result = await db.execute(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.action == "BLOCKED"
        )
    )
    blocked_events = blocked_result.scalar_one()

    return {
        "total_events": total_events,
        "detected_events": total_events,
        "blocked_events": blocked_events,
        "average_risk_score": average_score,
        "risk_levels": risk_levels,
        "attack_types": attack_types,
        "recent_events": [
            serialize_event(event)
            for event in recent_events
        ],
    }


# ============================================================
# IP INVESTIGATION
# ============================================================

@router.get("/ip/{ip_address}")
async def get_ip_security_history(
    ip_address: str,
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(SecurityEvent)
        .where(
            SecurityEvent.ip_address == ip_address
        )
        .order_by(
            desc(SecurityEvent.created_at)
        )
        .limit(limit)
    )

    events = result.scalars().all()

    # --------------------------------------------------------
    # Redis block status
    # --------------------------------------------------------

    block_key = (
        f"sentinel:block:{ip_address}"
    )

    blocked = False
    block_ttl = -1

    try:
        redis = redis_service.client

        blocked_value = await redis.get(
            block_key
        )

        if blocked_value:
            blocked = True
            block_ttl = await redis.ttl(
                block_key
            )

    except Exception:
        # Redis availability should not break
        # the database investigation endpoint.
        pass

    # --------------------------------------------------------
    # Attack distribution
    # --------------------------------------------------------

    attack_counts = Counter(
        event.attack_type
        for event in events
    )

    return {
        "ip_address": ip_address,
        "blocked": blocked,
        "block_ttl_seconds": (
            max(block_ttl, 0)
            if blocked
            else 0
        ),
        "event_count": len(events),
        "attack_types": dict(
            attack_counts
        ),
        "events": [
            serialize_event(event)
            for event in events
        ],
    }
