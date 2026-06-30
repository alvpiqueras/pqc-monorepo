from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ConfigureServerIdentityRequest(BaseModel):
    """
    Configure the server service identity for the distributed mTLS demo.

    The gateway sends the certificate material obtained from internal-ca.
    """

    service_id: str = Field(
        default="customer-api",
        description="Logical identifier of the server service.",
    )

    ca_certificate_pem: str = Field(
        description="PEM-encoded internal CA certificate.",
    )

    own_certificate_pem: str = Field(
        description="PEM-encoded certificate assigned to this server service.",
    )

    expected_client_subject: str = Field(
        default="billing-service.internal",
        description="Expected subject fragment for the client certificate.",
    )


class ServerIdentityStatusResponse(BaseModel):
    configured: bool

    service_id: str
    service_role: str

    expected_client_subject: Optional[str] = None

    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_dates: Optional[str] = None

    ca_certificate_loaded: bool
    own_certificate_loaded: bool

    measurements: Dict[str, float] = {}
    metadata: Dict[str, Any] = {}


class ConfigureServerIdentityResponse(BaseModel):
    configured: bool
    reason: str

    service_id: str
    service_role: str

    expected_client_subject: str

    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_dates: Optional[str] = None

    measurements: Dict[str, float]