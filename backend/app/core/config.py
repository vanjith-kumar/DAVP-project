from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Union
import json

class Settings(BaseSettings):
    APP_NAME: str = "SecureLog AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    SECRET_KEY: str
    SESSION_EXPIRE_MINUTES: int = 1440
    CORS_ORIGINS: Union[str, List[str]] = ["http://localhost:5173", "http://localhost:3000"]

    DATABASE_URL: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    def get_cors_origins(self) -> List[str]:
        if isinstance(self.CORS_ORIGINS, str):
            return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]
        return self.CORS_ORIGINS

settings = Settings()
