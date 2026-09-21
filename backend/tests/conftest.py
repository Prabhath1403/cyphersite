"""Test fixtures for CipherSight backend tests."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

from app.database import Base, get_db
from app.main import app as fastapi_app
from app.routers.auth import router as auth_router

fastapi_app.include_router(auth_router)


# Register SQLite compilation for PostgreSQL JSONB so SQLite in-memory tests can run
@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"

# Import all models so Base.metadata knows about them
import app.models  # noqa: F401

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest_asyncio.fixture()
async def db_engine():
    """Create a fresh async engine for each test."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()

@pytest_asyncio.fixture()
async def db_session(db_engine):
    """Create a fresh async session for each test."""
    session_factory = async_sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session

import uuid
from app.core.auth.security import get_current_active_user
from app.models.user import User

@pytest_asyncio.fixture()
async def client(db_session):
    """Async test client with DB and Auth overrides."""
    async def override_get_db():
        yield db_session

    mock_user = User(
        id=uuid.uuid4(),
        email='test@ciphersight.io',
        hashed_password='hashed',
        full_name='Test User',
        is_active=True,
        is_admin=False,
    )
    
    async def override_auth():
        return mock_user

    fastapi_app.dependency_overrides[get_db] = override_get_db
    fastapi_app.dependency_overrides[get_current_active_user] = override_auth
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    fastapi_app.dependency_overrides.clear()
