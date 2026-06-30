from typing import Any, Dict, List

from pydantic import BaseModel, Field


class ServerHandshakeStartRequest(BaseModel):
    """
    Request received by the server when the client starts Phase C1.

    The payload is still not encrypted in this phase. It is included only as
    application-level metadata for traceability.
    """

    operation: str = Field(
        default="handshake-only-demo",
        description="Logical operation requested by the gateway through the client.",
    )

    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Application-level metadata. Not encrypted in Phase C1.",
    )

    client_service_id: str = Field(
        default="billing-service",
        description="Logical identifier of the client service starting the handshake.",
    )

    phase: str = Field(
        default="C1-handshake-only",
        description="Current demo phase.",
    )


class ServerHandshakeStartResponse(BaseModel):
    handshake_started: bool
    session_id: str

    kem_algorithm: str
    kem_public_key_b64: str

    server_certificate_pem: str

    server_service: Dict[str, Any] = Field(default_factory=dict)
    steps: List[str] = Field(default_factory=list)
    measurements: Dict[str, float] = Field(default_factory=dict)