from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VerifyIntranetIdentityRequest(BaseModel):
    """
    Web-ready request model for verifying the identity of an internal HTTPS portal.

    Instead of sending PEM certificates directly, the client references previously
    registered certificate artifacts.
    """

    client_id: str = Field(
        default="corporate-browser-01",
        description="Identifier of the simulated internal corporate client.",
    )

    ca_artifact_id: str = Field(
        description="Artifact ID of the trusted internal CA certificate.",
        examples=["ca_8f3a2b1c4d5e6f70"],
    )

    server_certificate_id: str = Field(
        description="Artifact ID of the intranet server certificate.",
        examples=["srv_a19d44ef9021abcd"],
    )

    expected_subject: str = Field(
        default="intranet.local",
        description="Expected subject fragment for the intranet server certificate.",
        examples=["intranet.local"],
    )


class IntranetIdentityVerificationResponse(BaseModel):
    trusted: bool
    reason: str

    client: Dict[str, Any]
    server: Dict[str, Any]

    verification: Dict[str, Any]
    measurements: Dict[str, float]
    steps: List[str]


class HttpsConnectionDemoRequest(BaseModel):
    """
    Simulated HTTPS connection request using artifact IDs.
    """

    client_id: str = Field(
        default="corporate-browser-01",
        description="Identifier of the simulated internal corporate client.",
    )

    requested_resource: str = Field(
        default="/dashboard",
        description="Internal intranet resource requested by the client.",
    )

    ca_artifact_id: str = Field(
        description="Artifact ID of the trusted internal CA certificate.",
    )

    server_certificate_id: str = Field(
        description="Artifact ID of the intranet server certificate.",
    )

    expected_subject: str = Field(
        default="intranet.local",
        description="Expected identity of the internal HTTPS portal.",
    )


class HttpsConnectionDemoResponse(BaseModel):
    connection_allowed: bool
    reason: str

    client: Dict[str, Any]
    server: Dict[str, Any]

    identity_verification: IntranetIdentityVerificationResponse

    requested_resource: str
    resource_response: Optional[Dict[str, Any]] = None

    steps: List[str]
    measurements: Dict[str, float]

class SecureHttpsConnectionDemoRequest(BaseModel):
    """
    Simulated protected HTTPS connection after server certificate validation.

    This does not implement a real TLS handshake and does not use ML-KEM for
    key exchange. It represents the encrypted application-data phase after the
    client has accepted the server identity.
    """

    client_id: str = Field(
        default="corporate-browser-01",
        description="Identifier of the simulated internal corporate client.",
    )

    requested_resource: str = Field(
        default="/dashboard",
        description="Internal intranet resource requested by the client.",
    )

    http_method: str = Field(
        default="GET",
        description="HTTP method simulated inside the protected HTTPS channel.",
    )

    payload: str = Field(
        default="GET /dashboard HTTP/1.1",
        description="Application payload to encrypt with the simulated HTTPS session key.",
    )

    ca_artifact_id: str = Field(
        description="Artifact ID of the trusted internal CA certificate.",
    )

    server_certificate_id: str = Field(
        description="Artifact ID of the intranet server certificate.",
    )

    expected_subject: str = Field(
        default="intranet.local",
        description="Expected identity of the internal HTTPS portal.",
    )


class SecureHttpsConnectionDemoResponse(BaseModel):
    connection_established: bool
    reason: str

    client: Dict[str, Any]
    server: Dict[str, Any]

    session: Dict[str, Any]
    identity_verification: IntranetIdentityVerificationResponse

    encrypted_request: Optional[Dict[str, Any]] = None
    decrypted_at_server: Optional[Dict[str, Any]] = None

    steps: List[str]
    measurements: Dict[str, float]