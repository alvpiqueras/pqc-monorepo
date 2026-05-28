from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "api-mtls-sim"
    SERVICE_VERSION: str = "0.1.0"

    USE_CASE: str = "mutual-tls-service-to-service"
    TRUST_MODEL: str = "private-trust"
    COMPONENT_ROLE: str = "mtls-simulation-consumer"

    DEFAULT_CLIENT_SERVICE_ID: str = "billing-service"
    DEFAULT_SERVER_SERVICE_ID: str = "customer-api"

    DEFAULT_CLIENT_SUBJECT: str = "billing-service.internal"
    DEFAULT_SERVER_SUBJECT: str = "customer-api.internal"

    ARTIFACT_STORAGE_DIR: str = "artifacts"

    ALLOWED_ORIGINS: str = "*"

    class Config:
        env_file = ".env"


settings = Settings()