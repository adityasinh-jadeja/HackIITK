"""
Application configuration loaded from environment variables.
"""
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GEMINI_API_KEY: str = ""
    MONGODB_URI: str = "mongodb://localhost:27017/secure_browser"
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    MAX_PAGE_LOAD_TIMEOUT: int = 30000
    RISK_THRESHOLD_WARN: int = 40
    RISK_THRESHOLD_APPROVAL: int = 65
    RISK_THRESHOLD_BLOCK: int = 85
    PLAYWRIGHT_HEADLESS: bool = True
    MAX_CONCURRENT_CONTEXTS: int = 5

    class Config:
        env_file = ".env"

settings = Settings()
