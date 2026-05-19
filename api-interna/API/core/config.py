from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Central configuration for the internal APIs PQC use case.

    This API simulates service-to-service authentication and protected
    API-to-API communication inside a corporate private-trust environment.
    """

    SERVICE_NAME: str = "api-interna"
    SERVICE_VERSION: str = "1.0.0"

    USE_CASE: str = "internal-apis-microservices"
    TRUST_MODEL: str = "private-trust"

    INTERNAL_DOMAIN: str = "qcs.local"

    KEM_ALGORITHM: str = "ML-KEM-768"
    SIGNATURE_ALGORITHM: str = "ML-DSA-65"

    DEFAULT_REQUEST_VALIDITY_SECONDS: int = 300

    ALLOWED_ORIGINS: str = "*"

    class Config:
        env_file = ".env"


settings = Settings()