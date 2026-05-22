from typing import Optional, Any, Dict

from pydantic import BaseModel, Field


class GenerateCaRequest(BaseModel):
    """
    Request model for generating an internal PQC CA.

    The CA will be represented by a private key and a self-signed X.509
    certificate generated with OpenSSL.
    """

    common_name: str = Field(
        default="Internal PQC CA",
        description="Common Name for the internal CA certificate.",
        examples=["Internal PQC CA"],
    )
    organization: str = Field(
        default="TFM PQC Lab",
        description="Organization field for the CA certificate subject.",
        examples=["TFM PQC Lab"],
    )
    country: str = Field(
        default="ES",
        description="Country field for the certificate subject.",
        examples=["ES"],
    )
    signature_algorithm: str = Field(
        default="ML-DSA-65",
        description="Post-quantum signature algorithm used by the CA.",
        examples=["ML-DSA-65"],
    )
    validity_days: int = Field(
        default=365,
        ge=1,
        le=3650,
        description="Validity period of the CA certificate in days.",
        examples=[365],
    )


class GenerateCaResponse(BaseModel):
    ca_id: str
    common_name: str
    subject: str
    signature_algorithm: str
    private_key_path: str
    certificate_path: str
    certificate_pem: str
    message: str


class GenerateCsrRequest(BaseModel):
    """
    Request model for generating a service private key and CSR.

    This represents the usual flow where a service creates a keypair and
    asks the CA to certify its public identity.
    """

    common_name: str = Field(
        default="intranet.local",
        description="Common Name of the service certificate.",
        examples=["intranet.local"],
    )
    organization: str = Field(
        default="TFM PQC Lab",
        description="Organization field for the CSR subject.",
        examples=["TFM PQC Lab"],
    )
    country: str = Field(
        default="ES",
        description="Country field for the CSR subject.",
        examples=["ES"],
    )
    signature_algorithm: str = Field(
        default="ML-DSA-65",
        description="Algorithm used to generate the service keypair.",
        examples=["ML-DSA-65"],
    )


class GenerateCsrResponse(BaseModel):
    csr_id: str
    common_name: str
    subject: str
    signature_algorithm: str
    private_key_path: str
    csr_path: str
    csr_pem: str
    message: str


class IssueCertificateRequest(BaseModel):
    """
    Request model for issuing a certificate from an existing CSR.

    The CSR must have been generated previously by this internal-ca service.
    """

    ca_id: str = Field(
        description="Identifier of the CA that will sign the certificate.",
        examples=["ca-..."],
    )
    csr_id: str = Field(
        description="Identifier of the CSR to be signed.",
        examples=["csr-..."],
    )
    validity_days: int = Field(
        default=365,
        ge=1,
        le=3650,
        description="Validity period of the issued certificate in days.",
        examples=[365],
    )


class IssueCertificateResponse(BaseModel):
    certificate_id: str
    ca_id: str
    csr_id: str
    certificate_path: str
    certificate_pem: str
    message: str

class IssueCertificateFromPemRequest(BaseModel):
    """
    Request model for issuing a certificate from an externally generated CSR PEM.

    This is closer to a real PKI workflow: the service generates its own
    private key and CSR, and the CA only receives the CSR.
    """

    ca_id: str = Field(
        description="Identifier of the CA that will sign the certificate.",
        examples=["ca-abc123def456"],
    )
    csr_pem: str = Field(
        description="PEM-encoded Certificate Signing Request.",
        examples=[
            "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n"
        ],
    )
    validity_days: int = Field(
        default=365,
        ge=1,
        le=3650,
        description="Validity period of the issued certificate in days.",
        examples=[365],
    )


class IssueCertificateFromFileResponse(BaseModel):
    certificate_id: str
    ca_id: str
    uploaded_csr_id: str
    certificate_path: str
    certificate_pem: str
    message: str


class VerifyCertificateRequest(BaseModel):
    """
    Request model for verifying a certificate against an internal CA.
    """

    ca_id: str = Field(
        description="Identifier of the CA certificate used as trust anchor."
    )
    certificate_id: str = Field(
        description="Identifier of the certificate to verify."
    )


class VerifyCertificateResponse(BaseModel):
    valid: bool
    ca_id: str
    certificate_id: str
    reason: str
    openssl_output: Optional[str] = None


class CertificateInfoResponse(BaseModel):
    certificate_id: str
    certificate_text: str


class AvailableAlgorithmsResponse(BaseModel):
    standardized: list[str]
    note: str

class CaMetricsDemoResponse(BaseModel):
    """
    Metrics generated by a full internal CA demo flow.

    This endpoint measures the practical cost of issuing and verifying
    X.509 PQC certificates using OpenSSL.
    """

    signature_algorithm: str
    validity_days: int
    timings_ms: Dict[str, float]
    sizes_bytes: Dict[str, int]
    identifiers: Dict[str, str]
    verification_valid: bool
    notes: list[str]