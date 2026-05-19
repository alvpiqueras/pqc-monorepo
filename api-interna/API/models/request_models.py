from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class InternalApiRequestPayload(BaseModel):
    """
    Payload representing an internal API-to-API request.

    This is the object that will be signed with ML-DSA.
    """

    request_id: str
    service_id: str
    service_role: str
    target_api: str
    action: str
    resource: str
    issued_at: datetime
    expires_at: datetime
    claims: Dict[str, Any] = Field(default_factory=dict)


class SignInternalRequestInput(BaseModel):
    """
    Input model used to create and sign an internal API request.
    """

    service_id: str = Field(
        default="billing-service",
        examples=["billing-service"],
    )
    service_role: str = Field(
        default="consumer",
        examples=["consumer"],
    )
    target_api: str = Field(
        default="customer-api",
        examples=["customer-api"],
    )
    action: str = Field(
        default="read_customer_profile",
        examples=["read_customer_profile"],
    )
    resource: str = Field(
        default="/customers/123",
        examples=["/customers/123"],
    )
    private_key_b64: str = Field(
        description="Base64-encoded ML-DSA private key of the calling service."
    )
    validity_seconds: Optional[int] = Field(
        default=None,
        description="Validity window for the signed request.",
        examples=[300],
    )
    claims: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional internal claims attached to the request.",
    )


class SignedInternalApiRequest(BaseModel):
    """
    Signed internal API request.

    The request payload is signed with the service private key.
    """

    payload: InternalApiRequestPayload
    signature_algorithm: str
    signature_b64: str
    signed_payload_size_bytes: int
    signature_size_bytes: int
    signing_time_ms: float


class VerifyInternalRequestInput(BaseModel):
    """
    Input model used to verify a signed internal API request.
    """

    signed_request: SignedInternalApiRequest
    service_public_key_b64: str = Field(
        description="Base64-encoded ML-DSA public key of the calling service."
    )
    expected_target_api: str = Field(
        default="customer-api",
        examples=["customer-api"],
    )
    allowed_actions: List[str] = Field(
        default_factory=lambda: ["read_customer_profile"],
        description="Actions accepted by the target internal API.",
    )


class VerifyInternalRequestResponse(BaseModel):
    """
    Verification result for a signed internal API request.
    """

    valid: bool
    reason: str
    verified_with: str
    service_id: str
    target_api: str
    action: str
    verification_time_ms: float
    checked_at: datetime