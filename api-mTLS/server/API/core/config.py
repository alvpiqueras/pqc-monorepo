from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "server"
    SERVICE_VERSION: str = "0.3.0"

    SERVICE_ID: str = "customer-api"
    SERVICE_ROLE: str = "mtls-server"

    INTERNAL_DEMO_TOKEN: str = "dev-mtls-token"

    DEFAULT_KEM_ALGORITHM: str = "ML-KEM-768"
    HANDSHAKE_SESSION_TTL_SECONDS: int = 300

    class Config:
        env_file = ".env"


settings = Settings()