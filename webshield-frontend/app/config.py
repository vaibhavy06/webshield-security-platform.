from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "WebShield Security Scanner"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ZAP_API_KEY: Optional[str] = None
    
    # Infrastructure
    DATABASE_URL: str = "postgresql://postgres:postgres@db:5432/webshield"
    REDIS_URL: str = "redis://redis:6379/0"
    
    # Scanner Settings
    REQUEST_TIMEOUT: int = 10
    USER_AGENT: str = "WebShield/1.0 (Security Intelligence Engine)"

    class Config:
        env_file = ".env"

settings = Settings()
