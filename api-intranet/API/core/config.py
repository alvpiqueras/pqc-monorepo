from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "api-intranet"
    SERVICE_VERSION: str = "0.2.0"

    USE_CASE: str = "private-intranet-https"
    TRUST_MODEL: str = "private-trust"

    DEFAULT_EXPECTED_SUBJECT: str = "intranet.local"

    ALLOWED_ORIGINS: str = "*"

    class Config:
        env_file = ".env"


settings = Settings()