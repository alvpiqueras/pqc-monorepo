from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VerifyIntranetCertificateRequest(BaseModel):
    """
    Input model for verifying an intranet server certificate.

    The CA certificate and the server certificate are provided in PEM format.
    """

    ca_certificate_pem: str = Field(
        description="PEM-encoded internal CA certificate."
    )
    server_certificate_pem: str = Field(
        description="PEM-encoded intranet server certificate."
    )
    expected_subject: str = Field(
        default="intranet.local",
        description="Expected Common Name or subject fragment for the intranet server.",
        examples=["intranet.local"],
    )


class VerifyIntranetCertificateResponse(BaseModel):
    valid: bool
    reason: str
    expected_subject: str
    subject_matches: bool
    openssl_verify_output: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_dates: Optional[str] = None


class IntranetConnectRequest(BaseModel):
    """
    Simulated client connection request to a private intranet service.
    """

    client_id: str = Field(
        default="employee-001",
        description="Identifier of the simulated internal client.",
    )
    requested_resource: str = Field(
        default="/dashboard",
        description="Private intranet resource requested by the client.",
    )
    ca_certificate_pem: str = Field(
        description="PEM-encoded internal CA certificate."
    )
    server_certificate_pem: str = Field(
        description="PEM-encoded intranet server certificate."
    )
    expected_subject: str = Field(
        default="intranet.local",
        description="Expected intranet server identity.",
    )


class IntranetConnectResponse(BaseModel):
    connection_allowed: bool
    client_id: str
    requested_resource: str
    reason: str
    verification: VerifyIntranetCertificateResponse
    steps: List[str]
    resource_response: Optional[Dict[str, Any]] = None