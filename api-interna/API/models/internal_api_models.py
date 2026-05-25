from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VerifyServiceCertificateRequest(BaseModel):
    """
    Verify a calling service certificate against the internal CA certificate.
    """

    ca_certificate_pem: str = Field(
        description="PEM-encoded internal CA certificate."
    )
    service_certificate_pem: str = Field(
        description="PEM-encoded certificate presented by the calling service."
    )
    expected_service_subject: str = Field(
        default="billing-service.local",
        description="Expected subject fragment for the calling service.",
        examples=["billing-service.local"],
    )


class VerifyServiceCertificateResponse(BaseModel):
    valid: bool
    reason: str
    expected_service_subject: str
    subject_matches: bool
    openssl_verify_output: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_dates: Optional[str] = None


class ServiceCallRequest(BaseModel):
    """
    Simulated API-to-API request between internal microservices.
    """

    calling_service: str = Field(
        default="billing-service",
        description="Logical name of the calling microservice.",
    )
    target_api: str = Field(
        default="customer-api",
        description="Internal API being called.",
    )
    action: str = Field(
        default="read_customer_profile",
        description="Requested internal API action.",
    )
    resource: str = Field(
        default="/customers/123",
        description="Target resource inside the internal API.",
    )
    allowed_actions: List[str] = Field(
        default_factory=lambda: ["read_customer_profile"],
        description="Actions allowed by the target API.",
    )
    ca_certificate_pem: str = Field(
        description="PEM-encoded internal CA certificate."
    )
    service_certificate_pem: str = Field(
        description="PEM-encoded certificate presented by the calling service."
    )
    expected_service_subject: str = Field(
        default="billing-service.local",
        description="Expected certificate subject for the calling service.",
    )


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