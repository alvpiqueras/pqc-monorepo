import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    """
    Central configuration for the api-intranet service.

    This API represents a Private Trust scenario where an organization
    controls its own internal HTTPS services, trust anchors and
    cryptographic policy.
    """

    # Service metadata
    SERVICE_NAME: str = "api-intranet"
    SERVICE_DESCRIPTION: str = (
        "Private Trust laboratory API for simulating an internal HTTPS intranet "
        "protected with post-quantum cryptographic primitives."
    )
    SERVICE_VERSION: str = "0.1.0"

    # Private Trust scenario metadata
    TRUST_MODEL: str = "private-trust"
    USE_CASE: str = "internal-https-intranet"
    INTERNAL_DOMAIN: str = "intranet.qcs.local"
    INTERNAL_CA_NAME: str = "QCS Internal CA"

    # Default PQC algorithms
    KEM_ALGORITHM: str = "ML-KEM-768"
    SIGNATURE_ALGORITHM: str = "ML-DSA-65"

    # Certificate-like object configuration
    DEFAULT_CERT_VALIDITY_DAYS: int = 365

    # CORS configuration
    ALLOWED_ORIGINS: list[str] = field(
        default_factory=lambda: os.getenv("ALLOWED_ORIGINS", "*").split(",")
    )


settings = Settings()