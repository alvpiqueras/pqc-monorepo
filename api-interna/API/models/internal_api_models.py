from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

class VerifyServiceCertificateRequest(BaseModel):
    ca_certificate_pem: str
    service_certificate_pem: str
    expected_service_subject: str = "billing-service.local"

class VerifyServiceCertificateResponse(BaseModel):
    valid: bool
    reason: str
    expected_service_subject: str
    subject_matches: bool
    openssl_verify_output: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_dates: Optional[str] = None


class ServiceCallResponse(BaseModel):
    call_allowed: bool
    calling_service: str
    target_api: str
    action: str
    resource: str
    reason: str
    certificate_verification: VerifyServiceCertificateResponse
    authorization_result: Dict[str, Any]
    steps: List[str]
    api_response: Optional[Dict[str, Any]] = None
    

class ServiceCallWithPolicyResponse(BaseModel):
    call_allowed: bool
    identity_valid: bool
    authorization_valid: bool
    calling_service: str
    target_api: str
    action: str
    resource: str
    reason: str
    certificate_verification: VerifyServiceCertificateResponse
    authorization_result: Dict[str, Any]
    executed_action: Optional[str] = None
    api_response: Optional[Dict[str, Any]] = None
    steps: List[str]

class VerifyServiceCertificateByIdRequest(BaseModel):
    """
    Verify a calling service certificate using previously uploaded artifacts.
    """

    ca_artifact_id: str = Field(
        description="ID of the stored internal CA certificate artifact.",
        examples=["ca-art-abc123def456"],
    )
    service_certificate_id: str = Field(
        description="ID of the stored service certificate artifact.",
        examples=["svc-cert-abc123def456"],
    )
    expected_service_subject: str = Field(
        default="billing-service.local",
        description="Expected subject fragment for the calling service.",
        examples=["billing-service.local"],
    )

class AuthorizationCheckByIdRequest(BaseModel):
    """
    Check authorization using a previously uploaded authorization policy.
    """

    policy_id: str = Field(
        description="ID of the stored authorization policy artifact.",
        examples=["policy-abc123def456"],
    )
    calling_service: str = Field(
        default="billing-service",
        description="Service attempting to call the target API.",
    )
    target_api: str = Field(
        default="customer-api",
        description="Internal API being called.",
    )
    action: str = Field(
        default="read_customer_profile",
        description="Requested internal action.",
    )


class AuthorizationCheckResponse(BaseModel):
    authorization_valid: bool
    policy_id: str
    calling_service: str
    target_api: str
    requested_action: str
    allowed_actions: List[str]
    reason: str


class ServiceCallByIdRequest(BaseModel):
    """
    Simulated internal service call using stored artifacts.
    """

    ca_artifact_id: str
    service_certificate_id: str
    policy_id: str

    calling_service: str = "billing-service"
    target_api: str = "customer-api"
    action: str = "read_customer_profile"
    resource: str = "/customers/123"
    expected_service_subject: str = "billing-service.local"


class SecureServiceCallByIdRequest(BaseModel):
    """
    Simulated secure internal service call using:
    - stored CA certificate;
    - stored service certificate;
    - stored authorization policy;
    - ML-KEM session establishment;
    - AES-GCM payload encryption.
    """

    ca_artifact_id: str
    service_certificate_id: str
    policy_id: str

    calling_service: str = "billing-service"
    target_api: str = "customer-api"
    action: str = "read_customer_profile"
    resource: str = "/customers/123"
    expected_service_subject: str = "billing-service.local"

    plaintext_payload: Dict[str, Any] = Field(
        default_factory=lambda: {
            "customer_id": "123",
            "requested_fields": ["profile_status", "billing_visibility"],
        }
    )


class SecureServiceCallResponse(BaseModel):
    call_allowed: bool
    identity_valid: bool
    authorization_valid: bool
    kem_session_established: bool
    payload_encrypted: bool
    payload_decrypted: bool

    calling_service: str
    target_api: str
    action: str
    resource: str
    reason: str

    certificate_verification: VerifyServiceCertificateResponse
    authorization_result: Dict[str, Any]
    kem_session_layer: Dict[str, Any]
    payload_protection_layer: Dict[str, Any]
    execution_layer: Dict[str, Any]
    steps: List[str]