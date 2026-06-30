from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "gateway"
    SERVICE_VERSION: str = "0.2.0"

    USE_CASE: str = "distributed-application-level-mtls"
    TRUST_MODEL: str = "private-trust"
    COMPONENT_ROLE: str = "public-demo-orchestrator"

    INTERNAL_CA_URL: str = "https://internal-ca.onrender.com"
    CLIENT_SERVICE_URL: str = "http://localhost:8011"
    SERVER_SERVICE_URL: str = "http://localhost:8012"

    INTERNAL_DEMO_TOKEN: str = "dev-mtls-token"

    DEFAULT_CA_COMMON_NAME: str = "Distributed mTLS Internal CA"
    DEFAULT_CLIENT_SERVICE_ID: str = "billing-service"
    DEFAULT_SERVER_SERVICE_ID: str = "customer-api"

    DEFAULT_CLIENT_SUBJECT: str = "billing-service.internal"
    DEFAULT_SERVER_SUBJECT: str = "customer-api.internal"

    DEFAULT_SIGNATURE_ALGORITHM: str = "ML-DSA-65"
    DEFAULT_CERT_VALIDITY_DAYS: int = 365

    ALLOWED_ORIGINS: str = "*"

    class Config:
        env_file = ".env"


settings = Settings()