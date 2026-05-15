from datetime import datetime

from pydantic import BaseModel, Field


class KemKeypairResponse(BaseModel):
    """
    Response model for a generated ML-KEM keypair.

    The public and private keys are encoded in Base64 to make them suitable
    for JSON transport.
    """

    kem_algorithm: str
    public_key_b64: str
    private_key_b64: str
    public_key_size_bytes: int
    private_key_size_bytes: int
    generated_at: datetime


class EncapsulateRequest(BaseModel):
    """
    Request model for encapsulating a shared secret using the recipient's
    ML-KEM public key.
    """

    public_key_b64: str = Field(
        description="Base64-encoded ML-KEM public key."
    )


class EncapsulateResponse(BaseModel):
    """
    Response model for ML-KEM encapsulation.

    The ciphertext must be sent to the holder of the private key so that
    both parties can derive the same shared secret.
    """

    kem_algorithm: str
    ciphertext_b64: str
    shared_secret_b64: str
    ciphertext_size_bytes: int
    shared_secret_size_bytes: int
    encapsulated_at: datetime


class DecapsulateRequest(BaseModel):
    """
    Request model for decapsulating a shared secret using the recipient's
    ML-KEM private key and the received ciphertext.
    """

    private_key_b64: str = Field(
        description="Base64-encoded ML-KEM private key."
    )
    ciphertext_b64: str = Field(
        description="Base64-encoded ML-KEM ciphertext."
    )


class DecapsulateResponse(BaseModel):
    """
    Response model for ML-KEM decapsulation.
    """

    kem_algorithm: str
    shared_secret_b64: str
    shared_secret_size_bytes: int
    decapsulated_at: datetime