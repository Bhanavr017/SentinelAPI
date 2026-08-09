from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


def _ensure_columns(connection):
    inspector = inspect(connection)

    users = {
        column["name"]
        for column in inspector.get_columns("users")
    }
    events = {
        column["name"]
        for column in inspector.get_columns("security_events")
    }

    if "role" not in users:
        connection.execute(
            text(
                "ALTER TABLE users "
                "ADD COLUMN role VARCHAR(20) "
                "DEFAULT 'user' NOT NULL"
            )
        )

    additions = {
        "request_id": "VARCHAR(64) DEFAULT 'legacy' NOT NULL",
        "action": "VARCHAR(20) DEFAULT 'BLOCKED' NOT NULL",
        "source": "VARCHAR(40) DEFAULT 'detection' NOT NULL",
        "user_agent": "VARCHAR(500)",
    }

    for name, definition in additions.items():
        if name not in events:
            connection.execute(
                text(
                    f"ALTER TABLE security_events "
                    f"ADD COLUMN {name} {definition}"
                )
            )


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_columns)
