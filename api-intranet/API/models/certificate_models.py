from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class ServiceIdentityRequest(BaseModel):
    """
    Request model for generating an internal service identity.

    In a real corporate intranet, this identity would be associated with
    an internal DNS name, a service name and a trust domain controlled by
    the organization.
    """

    service_id: str = Field(
        default="intranet-core",
        description="Internal identifier of the intranet service.",
        examples=["intranet-core"],
    )
    internal_dns: str = Field(
        default="intranet.qcs.local",
        description="Internal DNS name used by the corporate intranet service.",
        examples=["intranet.qcs.local"],
    )


class ServiceIdentityResponse(BaseModel):
    """
    Response model containing the generated service identity.

    The public key is encoded in Base64 so it can be transported easily
    through JSON.
    """

    service_id: str
    internal_dns: str
    trust_model: str
    signature_algorithm: str
    public_key_b64: str
    private_key_b64: str
    generated_at: datetime


class CertificateIssueRequest(BaseModel):
    """
    Request model for issuing a simplified internal certificate.

    This is not a full X.509 certificate. It is a controlled academic
    representation of the fields that are relevant for the TFM use case:
    subject, issuer, validity, public key, usage and post-quantum signature.
    """

    subject: str = Field(
        default="intranet.qcs.local",
        description="Internal DNS name or identity associated with the service.",
        examples=["intranet.qcs.local"],
    )
    service_id: str = Field(
        default="intranet-core",
        description="Internal identifier of the service.",
        examples=["intranet-core"],
    )
    public_key_b64: str = Field(
        description="Base64-encoded public key of the service."
    )
    usage: List[str] = Field(
        default_factory=lambda: ["server-auth", "internal-https"],
        description="Allowed usages for this internal certificate-like object.",
    )
    validity_days: Optional[int] = Field(
        default=None,
        description="Validity period in days. If omitted, the default API configuration is used.",
        examples=[365],
    )


class InternalCertificate(BaseModel):
    """
    Simplified internal certificate-like object.

    This object models the conceptual role of an internal HTTPS certificate
    without requiring a complete X.509 implementation in the first version.
    """

    subject: str
    service_id: str
    issuer: str
    trust_model: str
    public_key_algorithm: str
    public_key_b64: str
    usage: List[str]
    valid_from: datetime
    valid_to: datetime
    signature_algorithm: str
    signature_b64: str


class CertificateVerifyRequest(BaseModel):
    """
    Request model for verifying an internal certificate-like object.
    """

    certificate: InternalCertificate


class CertificateVerifyResponse(BaseModel):
    """
    Response model returned after certificate verification.
    """

    valid: bool
    reason: str
    verified_with: str
    subject: str
    issuer: str
    checked_at: datetime