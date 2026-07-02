from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "VDI Backend API"
    
    # Database
    DATABASE_URL: str
    
    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440 # 24 hours
    
    # Session (Starlette)
    SESSION_SECRET: str
    
    # Google OAuth
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    
    # Netbird settings
    NETBIRD_API_URL: str = "https://api.netbird.io/api"
    NETBIRD_API_TOKEN: str = ""
    AGENT_SECRET_KEY: str = "super_secret_agent_key_change_me"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

settings = Settings()
