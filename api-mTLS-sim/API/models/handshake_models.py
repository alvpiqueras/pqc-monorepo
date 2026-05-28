from typing import Any, Dict, List

from pydantic import BaseModel, Field


class MutualIdentityVerificationRequest(BaseModel):
    """
    Request model for mutual identity verification in the mTLS simulation.

    Both certificates must have been previously registered as artifacts.
    """

    client_service_id: str = Field(
        default="billing-service",
        description="Identifier of the service initiating the connection.",
        examples=["billing-service"],
    )

    server_service_id: str = Field(
        default="customer-api",
        description="Identifier of the service receiving the connection.",
        examples=["customer-api"],
    )

    ca_artifact_id: str = Field(
        description="Artifact ID of the trusted internal CA certificate.",
        examples=["ca_8f3a2b1c4d5e6f70"],
    )

    client_certificate_id: str = Field(
        description="Artifact ID of the client service certificate.",
        examples=["client_a19d44ef9021abcd"],
    )

    server_certificate_id: str = Field(
        description="Artifact ID of the server service certificate.",
        examples=["server_9af31e7d2b6c88a1"],
    )

    expected_client_subject: str = Field(
        default="billing-service.internal",
        description="Expected subject fragment for the client service certificate.",
        examples=["billing-service.internal"],
    )

    expected_server_subject: str = Field(
        default="customer-api.internal",
        description="Expected subject fragment for the server service certificate.",
        examples=["customer-api.internal"],
    )


class CertificateVerificationResult(BaseModel):
    valid: bool
    reason: str

    expected_subject: str
    subject_matches: bool

    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_dates: str | None = None
    openssl_verify_output: str | None = None


class MutualIdentityVerificationResponse(BaseModel):
    mutual_trust_established: bool
    reason: str

    client_service: Dict[str, Any]
    server_service: Dict[str, Any]

    client_verifies_server: CertificateVerificationResult
    server_verifies_client: CertificateVerificationResult

    steps: List[str]
    measurements: Dict[str, float]