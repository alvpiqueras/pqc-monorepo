from typing import Any, Dict, Optional

from pydantic import BaseModel


class StoredArtifactResponse(BaseModel):
    artifact_id: str
    artifact_type: str
    filename: str
    path: str
    size_bytes: int
    message: str


class StoredPolicyResponse(BaseModel):
    policy_id: str
    artifact_type: str
    filename: str
    path: str
    size_bytes: int
    parsed_policy: Dict[str, Any]
    message: str


class ArtifactInfoResponse(BaseModel):
    artifact_id: str
    artifact_type: str
    filename: str
    path: str
    size_bytes: int
    preview: Optional[str] = None