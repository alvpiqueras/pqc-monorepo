from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class BootstrapFromInternalCaRequest(BaseModel):
    """
    Request model for bootstrapping the distributed mTLS demo from internal-ca.
    """

    ca_common_name: str = Field(
        default="Distributed mTLS Internal CA",
        description="Common Name for the generated internal CA.",
    )

    client_common_name: str = Field(
        default="billing-service.internal",
        description="Common Name for the client service certificate.",
    )

    server_common_name: str = Field(
        default="customer-api.internal",
        description="Common Name for the server service certificate.",
    )

    signature_algorithm: str = Field(
        default="ML-DSA-65",
        description="PQC signature algorithm requested from internal-ca.",
    )

    validity_days: int = Field(
        default=365,
        ge=1,
        le=3650,
        description="Validity period for the issued certificates.",
    )


class InternalCaArtifactSummary(BaseModel):
    ca_id: Optional[str] = None
    client_csr_id: Optional[str] = None
    server_csr_id: Optional[str] = None
    client_certificate_id: Optional[str] = None
    server_certificate_id: Optional[str] = None

    ca_subject: Optional[str] = None
    client_subject: Optional[str] = None
    server_subject: Optional[str] = None

    signature_algorithm: Optional[str] = None


class ServiceConfigurationSummary(BaseModel):
    configured: bool
    service_id: str
    service_role: str
    expected_peer_subject: str
    status_response: Dict[str, Any]


class BootstrapFromInternalCaResponse(BaseModel):
    bootstrap_completed: bool
    reason: str

    internal_ca: InternalCaArtifactSummary

    client_service: ServiceConfigurationSummary
    server_service: ServiceConfigurationSummary

    steps: List[str]
    measurements: Dict[str, float]


class BootstrapStatusResponse(BaseModel):
    bootstrap_completed: bool
    reason: str

    gateway: Dict[str, Any]
    internal_ca: Dict[str, Any]
    client_service: Dict[str, Any]
    server_service: Dict[str, Any]

    latest_bootstrap: Optional[Dict[str, Any]] = None