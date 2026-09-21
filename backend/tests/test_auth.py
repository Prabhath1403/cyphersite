import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
import uuid
from app.main import app as fastapi_app
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.main import app as fastapi_app
from app.routers.auth import router as auth_router
from app.database import get_db

# Include router if not already included
if not any(route.path == "/api/auth/register" for route in fastapi_app.routes):
    fastapi_app.include_router(auth_router)

@pytest_asyncio.fixture()
async def unauth_client(db_session):
    async def override_get_db():
        yield db_session
    
    fastapi_app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    fastapi_app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_register_user(unauth_client):
    response = await unauth_client.post("/api/auth/register", json={
        "email": "newuser@ciphersight.io",
        "password": "securepassword",
        "full_name": "New User"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@ciphersight.io"
    assert "id" in data
    assert "password" not in data

@pytest.mark.asyncio
async def test_register_duplicate_email(unauth_client):
    # Register first
    await unauth_client.post("/api/auth/register", json={
        "email": "dupuser@ciphersight.io",
        "password": "securepassword",
        "full_name": "Dup User"
    })
    # Register duplicate
    response = await unauth_client.post("/api/auth/register", json={
        "email": "dupuser@ciphersight.io",
        "password": "securepassword2",
        "full_name": "Dup User 2"
    })
    assert response.status_code == 400

@pytest.mark.asyncio
async def test_login_success(unauth_client):
    await unauth_client.post("/api/auth/register", json={
        "email": "loginuser@ciphersight.io",
        "password": "loginpassword",
        "full_name": "Login User"
    })
    response = await unauth_client.post("/api/auth/login", json={
        "email": "loginuser@ciphersight.io",
        "password": "loginpassword"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_login_wrong_password(unauth_client):
    await unauth_client.post("/api/auth/register", json={
        "email": "wrongpass@ciphersight.io",
        "password": "rightpassword"
    })
    response = await unauth_client.post("/api/auth/login", json={
        "email": "wrongpass@ciphersight.io",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_nonexistent_user(unauth_client):
    response = await unauth_client.post("/api/auth/login", json={
        "email": "nonexistent@ciphersight.io",
        "password": "somepassword"
    })
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_get_me_authenticated(unauth_client):
    await unauth_client.post("/api/auth/register", json={
        "email": "meuser@ciphersight.io",
        "password": "mepassword",
        "full_name": "Me User"
    })
    login_resp = await unauth_client.post("/api/auth/login", json={
        "email": "meuser@ciphersight.io",
        "password": "mepassword"
    })
    token = login_resp.json()["access_token"]
    
    me_resp = await unauth_client.get("/api/auth/me", headers={
        "Authorization": f"Bearer {token}"
    })
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "meuser@ciphersight.io"

@pytest.mark.asyncio
async def test_get_me_no_token(unauth_client):
    response = await unauth_client.get("/api/auth/me")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_protected_endpoint_no_token(unauth_client):
    response = await unauth_client.get("/api/scans/dashboard")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_protected_endpoint_with_token(unauth_client):
    await unauth_client.post("/api/auth/register", json={
        "email": "protuser@ciphersight.io",
        "password": "protpassword"
    })
    login_resp = await unauth_client.post("/api/auth/login", json={
        "email": "protuser@ciphersight.io",
        "password": "protpassword"
    })
    token = login_resp.json()["access_token"]
    
    response = await unauth_client.get("/api/scans/dashboard", headers={
        "Authorization": f"Bearer {token}"
    })
    # Even if it's 200 or 500 (db state), it shouldn't be 401
    assert response.status_code != 401
