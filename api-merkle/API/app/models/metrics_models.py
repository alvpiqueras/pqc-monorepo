from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class MerkleMetricsDemoRequest(BaseModel):
    entries_count: int = Field(
        default=16,
        ge=2,
        le=4096,
        description="Number of synthetic registry entries used to build the Merkle tree.",
    )

    iterations: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Number of repetitions used to compute average measurements.",
    )

    proof_index: Optional[int] = Field(
        default=None,
        description=(
            "Leaf index used for inclusion proof generation. If omitted, the "
            "middle leaf is selected."
        ),
    )

    signature_algorithm: str = Field(
        default="ML-DSA-65",
        description="PQC signature algorithm used to sign the Merkle root.",
    )

    @field_validator("proof_index")
    @classmethod
    def validate_proof_index(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value < 0:
            raise ValueError("proof_index cannot be negative.")
        return value


class MerkleMetricsDemoResponse(BaseModel):
    entries_count: int
    iterations: int
    proof_index: int

    hash_algorithm: str
    signature_algorithm: str

    validation: Dict[str, bool]
    structure: Dict[str, Any]
    measurements: Dict[str, float]
    sizes_bytes: Dict[str, int]

    notes: list[str]