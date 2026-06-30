from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ConfigureClientIdentityRequest(BaseModel):
    """
    Configure the client service identity for the distributed mTLS demo.

    The gateway sends the certificate material obtained from internal-ca.
    """

    service_id: str = Field(
        default="billing-service",
        description="Logical identifier of the client service.",
    )

    ca_certificate_pem: str = Field(
        description="PEM-encoded internal CA certificate.",
    )

    own_certificate_pem: str = Field(
        description="PEM-encoded certificate assigned to this client service.",
    )

    expected_server_subject: str = Field(
        default="customer-api.internal",
        description="Expected subject fragment for the server certificate.",
    )

    server_service_url: str = Field(
        default="http://server:8000",
        description="Internal URL used by the client service to call the server service.",
    )


class ClientIdentityStatusResponse(BaseModel):
    configured: bool

    service_id: str
    service_role: str

    expected_server_subject: Optional[str] = None
    server_service_url: Optional[str] = None

    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_dates: Optional[str] = None

    ca_certificate_loaded: bool
    own_certificate_loaded: bool

    measurements: Dict[str, float] = {}
    metadata: Dict[str, Any] = {}


class ConfigureClientIdentityResponse(BaseModel):
    configured: bool
    reason: str

    service_id: str
    service_role: str

    expected_server_subject: str
    server_service_url: str

    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_dates: Optional[str] = None

    measurements: Dict[str, float]