from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ClientHandshakeRequest(BaseModel):
    """
    Request received by the client service from the gateway for Phase C1.

    The payload is still not encrypted in this phase. It is included only as
    application-level metadata for traceability.
    """

    operation: str = Field(
        default="handshake-only-demo",
        description="Logical operation requested by the gateway.",
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Application-level metadata. Not encrypted in Phase C1.",
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