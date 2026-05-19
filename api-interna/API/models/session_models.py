from datetime import datetime

from pydantic import BaseModel, Field


class KemKeypairResponse(BaseModel):
    kem_algorithm: str
    public_key_b64: str
    private_key_b64: str
    generated_at: datetime


class EncapsulateRequest(BaseModel):
    public_key_b64: str = Field(
        description="Base64-encoded ML-KEM public key."
    )


class EncapsulateResponse(BaseModel):
    kem_algorithm: str
    ciphertext_b64: str
    shared_secret_b64: str
    encapsulation_time_ms: float
    encapsulated_at: datetime


class DecapsulateRequest(BaseModel):
    private_key_b64: str = Field(
        description="Base64-encoded ML-KEM private key."
    )
    ciphertext_b64: str = Field(
        description="Base64-encoded ML-KEM ciphertext."
    )


class DecapsulateResponse(BaseModel):
    kem_algorithm: str
    shared_secret_b64: str
    decapsulation_time_ms: float
    decapsulated_at: datetime