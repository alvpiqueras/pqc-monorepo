from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "api-intranet"
    SERVICE_VERSION: str = "0.3.0"

    USE_CASE: str = "private-intranet-https"
    TRUST_MODEL: str = "private-trust"

    DEFAULT_EXPECTED_SUBJECT: str = "intranet.local"
    DEFAULT_CLIENT_ID: str = "corporate-browser-01"
    DEFAULT_PORTAL_ID: str = "intranet-portal"

    ALLOWED_ORIGINS: str = "*"

    ARTIFACT_STORAGE_DIR: str = "artifacts"

    class Config:
        env_file = ".env"


settings = Settings()