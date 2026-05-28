from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.config import settings
from models.handshake_models import MutualIdentityVerificationResponse


class SecureServiceExchangeRequest(BaseModel):
    """
    Request model for the full mTLS simulation demo.

    This endpoint simulates:
    - mutual certificate authentication;
    - ML-KEM session establishment;
    - AES-GCM protected request;
    - AES-GCM protected response.
    """

    client_service_id: str = Field(
        default=settings.DEFAULT_CLIENT_SERVICE_ID,
        description="Identifier of the service initiating the connection.",
        examples=["billing-service"],
    )

    server_service_id: str = Field(
        default=settings.DEFAULT_SERVER_SERVICE_ID,
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
        default=settings.DEFAULT_CLIENT_SUBJECT,
        description="Expected subject fragment for the client service certificate.",
        examples=["billing-service.internal"],
    )

    expected_server_subject: str = Field(
        default=settings.DEFAULT_SERVER_SUBJECT,
        description="Expected subject fragment for the server service certificate.",
        examples=["customer-api.internal"],
    )

    action: str = Field(
        default="read_customer_profile",
        description="Application-level action requested by the client service.",
    )

    resource: str = Field(
        default="/customers/123",
        description="Target resource requested through the simulated secure channel.",
    )

    plaintext_payload: str = Field(
        default='{"customer_id":"123","fields":["name","status"]}',
        description="Payload encrypted by the client and sent to the server.",
    )

    kem_algorithm: str = Field(
        default=settings.DEFAULT_KEM_ALGORITHM,
        description="ML-KEM/Kyber algorithm used for simulated session establishment.",
        examples=["ML-KEM-768", "Kyber768"],
    )


class SecureServiceExchangeResponse(BaseModel):
    exchange_completed: bool
    reason: str

    client_service: Dict[str, Any]
    server_service: Dict[str, Any]

    mutual_identity_verification: MutualIdentityVerificationResponse

    session: Dict[str, Any]

    encrypted_request: Optional[Dict[str, Any]] = None
    server_processing: Optional[Dict[str, Any]] = None
    encrypted_response: Optional[Dict[str, Any]] = None
    client_received_response: Optional[Dict[str, Any]] = None

    steps: List[str]
    measurements: Dict[str, float]