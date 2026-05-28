from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "mtls-client-service"
    SERVICE_VERSION: str = "0.1.0"

    SERVICE_ID: str = "billing-service"
    SERVICE_ROLE: str = "mtls-client"

    SERVER_SERVICE_URL: str = "http://localhost:8012"
    INTERNAL_DEMO_TOKEN: str = "dev-mtls-token"

    class Config:
        env_file = ".env"


settings = Settings()