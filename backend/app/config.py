"""CipherSight application configuration via pydantic BaseSettings."""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "CipherSight"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:80"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://ciphersight:ciphersight_pass@db:5432/ciphersight"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # Celery
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/1"

    # JWT Auth
    SECRET_KEY: str = "change-this-to-a-strong-random-secret-key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # Artifacts
    ARTIFACTS_DIR: str = "/app/artifacts"

    # AI Explanation Agent
    AI_PROVIDER: str = "deterministic"
    AI_API_KEY: str = ""
    AI_MODEL: str = "gpt-4o-mini"
    AI_API_BASE: str = "https://api.openai.com/v1"

    # Neo4j Graph Database
    NEO4J_URI: str = "bolt://neo4j:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "cyphercite123"

    # GitHub API
    GITHUB_TOKEN: str = ""

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from comma-separated string."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
