from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "mtls-gateway-api"
    SERVICE_VERSION: str = "0.1.0"

    USE_CASE: str = "distributed-application-level-mtls"
    TRUST_MODEL: str = "private-trust"
    COMPONENT_ROLE: str = "public-demo-orchestrator"

    INTERNAL_CA_URL: str = "http://localhost:8002"
    CLIENT_SERVICE_URL: str = "http://localhost:8011"
    SERVER_SERVICE_URL: str = "http://localhost:8012"

    INTERNAL_DEMO_TOKEN: str = "dev-mtls-token"

    ALLOWED_ORIGINS: str = "*"

    class Config:
        env_file = ".env"


settings = Settings()