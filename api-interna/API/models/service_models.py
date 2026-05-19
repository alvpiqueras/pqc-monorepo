from datetime import datetime

from pydantic import BaseModel, Field


class ServiceIdentityRequest(BaseModel):
    """
    Request model for generating a PQC identity for an internal service.
    """

    service_id: str = Field(
        default="billing-service",
        description="Internal identifier of the service.",
        examples=["billing-service"],
    )
    service_role: str = Field(
        default="consumer",
        description="Role of the service inside the internal architecture.",
        examples=["consumer", "producer", "orchestrator"],
    )


class ServiceIdentityResponse(BaseModel):
    """
    Response model containing the generated service identity.
    """

    service_id: str
    service_role: str
    internal_domain: str
    trust_model: str
    signature_algorithm: str
    public_key_b64: str
    private_key_b64: str
    generation_time_ms: float
    generated_at: datetime