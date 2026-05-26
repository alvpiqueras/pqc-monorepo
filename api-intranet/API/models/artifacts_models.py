from typing import Dict, Literal, Optional

from pydantic import BaseModel, Field


ArtifactType = Literal["ca_certificate", "server_certificate"]


class CertificateArtifactUploadResponse(BaseModel):
    artifact_id: str
    artifact_type: ArtifactType

    subject: str
    issuer: str
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    public_key_algorithm: Optional[str] = None

    created_at: str

    measurements: Dict[str, float] = Field(
        default_factory=dict,
        description="Timing measurements in milliseconds.",
    )


class CertificateArtifactResponse(BaseModel):
    artifact_id: str
    artifact_type: ArtifactType

    pem: str
    metadata: Dict[str, str]
    created_at: str


class CertificateArtifactSummary(BaseModel):
    artifact_id: str
    artifact_type: ArtifactType

    subject: str
    issuer: str
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    signature_algorithm: Optional[str] = None

    created_at: str


class ArtifactListResponse(BaseModel):
    artifacts: list[CertificateArtifactSummary]
    total: int