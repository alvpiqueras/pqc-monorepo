from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVICE_NAME: str = "internal-ca"
    SERVICE_VERSION: str = "0.1.0"

    TRUST_MODEL: str = "private-trust"
    COMPONENT_ROLE: str = "internal-pqc-certificate-authority"

    DEFAULT_CA_SUBJECT: str = "/CN=Internal PQC CA/O=TFM PQC Lab/C=ES"
    DEFAULT_CERT_DAYS: int = 365
    DEFAULT_SIGNATURE_ALGORITHM: str = "ML-DSA-65"

    STORAGE_DIR: Path = Path("/tmp/internal-ca")
    CERTIFICATES_DIR: Path = STORAGE_DIR / "certificates"
    KEYS_DIR: Path = STORAGE_DIR / "keys"
    CSRS_DIR: Path = STORAGE_DIR / "csrs"

    ALLOWED_ORIGINS: str = "*"

    class Config:
        env_file = ".env"


settings = Settings()