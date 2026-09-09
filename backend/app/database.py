"""Database engine, session, and base model configuration."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""
    pass


async def get_db() -> AsyncSession:
    """Dependency to yield an async database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all database tables and apply non-destructive schema migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Auto-migrate any columns added across platform phases for existing volumes
        await conn.execute(
            text("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS scan_type VARCHAR(50) NOT NULL DEFAULT 'network';")
        )
        await conn.execute(
            text("""
                ALTER TABLE crypto_assets
                  ADD COLUMN IF NOT EXISTS primitive VARCHAR(30),
                  ADD COLUMN IF NOT EXISTS mode VARCHAR(30),
                  ADD COLUMN IF NOT EXISTS padding VARCHAR(30),
                  ADD COLUMN IF NOT EXISTS usage VARCHAR(50),
                  ADD COLUMN IF NOT EXISTS repository VARCHAR(500),
                  ADD COLUMN IF NOT EXISTS confidence FLOAT,
                  ADD COLUMN IF NOT EXISTS evidence JSONB,
                  ADD COLUMN IF NOT EXISTS quantum_status VARCHAR(30),
                  ADD COLUMN IF NOT EXISTS risk_level VARCHAR(10),
                  ADD COLUMN IF NOT EXISTS sensitivity VARCHAR(30),
                  ADD COLUMN IF NOT EXISTS sensitivity_confidence FLOAT;
            """)
        )
