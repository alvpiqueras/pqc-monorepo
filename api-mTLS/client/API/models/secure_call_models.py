from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ClientHandshakeRequest(BaseModel):
    """
    Request received by the client service from the gateway for the handshake demo.

    The payload is still not encrypted here. It is included only as
    application-level metadata for traceability.
    """

    operation: str = Field(
        default="handshake-only-demo",
        description="Logical operation requested by the gateway.",
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Application-level metadata. Not encrypted in the handshake-only step.",
    )


class ServerHandshakeResponse(BaseModel):
    """
    Response expected from server /server/handshake/start.
    """

    handshake_started: bool
    session_id: str

    kem_algorithm: str
    kem_public_key_b64: str

    server_certificate_pem: str

    server_service: Dict[str, Any] = Field(default_factory=dict)
    steps: List[str] = Field(default_factory=list)
    measurements: Dict[str, float] = Field(default_factory=dict)


class CertificateVerificationResult(BaseModel):
    verified: bool
    trust_chain_verified: bool
    subject_matches_expected_identity: bool

    expected_subject_fragment: str
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_dates: Optional[str] = None

    openssl_verify_output: Optional[str] = None
    openssl_verify_error: Optional[str] = None

    measurements: Dict[str, float] = Field(default_factory=dict)


class ClientHandshakeResponse(BaseModel):
    handshake_completed: bool
    reason: str

    client_service: Dict[str, Any]
    server_handshake: Dict[str, Any]
    certificate_verification: Dict[str, Any]

    steps: List[str]
    measurements: Dict[str, float]


class ClientEncryptedRequestRequest(BaseModel):
    """
    Request received by the client service from the gateway for the encrypted
    request demo.
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
        description="Application payload that will be encrypted by the client.",
    )


class ServerSecureEndpointResponse(BaseModel):
    """
    Response expected from server /server/secure-endpoint.
    """

    secure_request_processed: bool
    request_decrypted_by_server: bool
    server_verified_client_certificate: bool

    reason: str

    decrypted_payload: Optional[Dict[str, Any]] = None

    client_certificate_verification: Dict[str, Any]
    kem: Dict[str, Any]
    encryption: Dict[str, Any]

    server_service: Dict[str, Any]

    steps: List[str]
    measurements: Dict[str, float]


class ClientEncryptedRequestResponse(BaseModel):
    encrypted_request_completed: bool

    request_encrypted_by_client: bool
    request_decrypted_by_server: bool

    client_verified_server_certificate: bool
    server_verified_client_certificate: bool

    reason: str

    client_service: Dict[str, Any]
    server_handshake: Dict[str, Any]
    certificate_verification: Dict[str, Any]

    kem: Dict[str, Any]
    encryption: Dict[str, Any]

    server_response: Dict[str, Any]

    steps: List[str]
    measurements: Dict[str, float]