from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String
from app.services.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(64), nullable=False, index=True, default="legacy")
    ip_address = Column(String(64), nullable=False, index=True)
    method = Column(String(16), nullable=False)
    path = Column(String(500), nullable=False)
    attack_type = Column(String(255), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    action = Column(String(20), nullable=False, default="BLOCKED")
    source = Column(String(40), nullable=False, default="detection")
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
