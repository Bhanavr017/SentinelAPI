from sqlalchemy.ext.asyncio import AsyncSession
from app.models.security_event import SecurityEvent


async def create_security_event(
    db: AsyncSession,
    *,
    request_id: str,
    ip_address: str,
    method: str,
    path: str,
    attack_type: str,
    risk_score: int,
    risk_level: str,
    action: str = "BLOCKED",
    source: str = "detection",
    user_agent: str = "",
) -> SecurityEvent:
    event = SecurityEvent(
        request_id=request_id,
        ip_address=ip_address,
        method=method,
        path=path,
        attack_type=attack_type,
        risk_score=risk_score,
        risk_level=risk_level,
        action=action,
        source=source,
        user_agent=user_agent,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event
