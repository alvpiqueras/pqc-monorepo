from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class HandshakeDemoRequest(BaseModel):
    """
    Request model for the handshake demo.

    The gateway receives a frontend-friendly request and asks the client service
    to initiate a handshake with the server service.
    """

    operation: str = Field(
        default="handshake-only-demo",
        description="Logical operation requested by the gateway.",
    )

    payload: Dict[str, Any] = Field(
        default_factory=lambda: {
            "customer_id": "cust-001",
            "requested_by": "billing-service",
            "purpose": "handshake-demo",
        },
        description="Application-level payload metadata. It is not encrypted in this step.",
    )


class HandshakeDemoResponse(BaseModel):
    handshake_completed: bool
    reason: str

    scope_note: str

    client_service: Dict[str, Any]
    server_handshake: Dict[str, Any]
    certificate_verification: Dict[str, Any]

    steps: List[str]
    measurements: Dict[str, float]

    raw_client_response: Optional[Dict[str, Any]] = None


class EncryptedRequestDemoRequest(BaseModel):
    """
    Request model for the encrypted service-to-service request demo.

    The gateway asks the client service to establish a shared secret with the
    server and send an AES-GCM encrypted application payload.
    """

    operation: str = Field(
        default="get-customer-risk-profile",
        description="Logical operation requested by the gateway.",
    )

    payload: Dict[str, Any] = Field(
        default_factory=lambda: {
            "customer_id": "cust-001",
            "requested_by": "billing-service",
            "purpose": "internal-risk-check",
        },
        description="Application payload that will be encrypted by the client service.",
    )


class EncryptedRequestDemoResponse(BaseModel):
    encrypted_request_completed: bool

    request_encrypted_by_client: bool
    request_decrypted_by_server: bool

    client_verified_server_certificate: bool
    server_verified_client_certificate: bool

    reason: str
    scope_note: str

    client_service: Dict[str, Any]
    server_handshake: Dict[str, Any]
    certificate_verification: Dict[str, Any]

    kem: Dict[str, Any]
    encryption: Dict[str, Any]

    server_response: Dict[str, Any]

    steps: List[str]
    measurements: Dict[str, float]

    raw_client_response: Optional[Dict[str, Any]] = None