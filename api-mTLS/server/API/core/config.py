from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "mtls-server-service"
    SERVICE_VERSION: str = "0.1.0"

    SERVICE_ID: str = "customer-api"
    SERVICE_ROLE: str = "mtls-server"

    INTERNAL_DEMO_TOKEN: str = "dev-mtls-token"

    class Config:
        env_file = ".env"


settings = Settings()