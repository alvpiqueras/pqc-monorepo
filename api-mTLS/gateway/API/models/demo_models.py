from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class HandshakeDemoRequest(BaseModel):
    """
    Request model for Phase C1.

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
            "purpose": "phase-c1-handshake-demo",
        },
        description="Application-level payload metadata. It is not encrypted in Phase C1.",
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