from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "api-interna"
    SERVICE_VERSION: str = "0.2.0"

    USE_CASE: str = "internal-apis-microservices"
    TRUST_MODEL: str = "private-trust"

    CALLING_SERVICE_DEFAULT_SUBJECT: str = "billing-service.local"
    TARGET_API_DEFAULT_NAME: str = "customer-api"

    ALLOWED_ORIGINS: str = "*"

    class Config:
        env_file = ".env"


settings = Settings()