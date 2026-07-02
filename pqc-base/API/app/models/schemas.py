from typing import Dict

from pydantic import BaseModel, Field, field_validator


# ============================================================
# Common response structures
# ============================================================

class Measurements(BaseModel):
    """
    Generic timing measurements in milliseconds.

    The exact keys depend on the operation:
    - keypair_generation_ms
    - encapsulation_ms
    - decapsulation_ms
    - signature_generation_ms
    - signature_verification_ms
    - total_operation_ms
    """

    measurements: Dict[str, float] = Field(
        default_factory=dict,
        description="Timing measurements in milliseconds.",
    )


class SizesBytes(BaseModel):
    """
    Generic size measurements in bytes.

    The exact keys depend on the operation:
    - public_key
    - secret_key
    - ciphertext
    - shared_secret
    - signature
    - message
    """

    sizes_bytes: Dict[str, int] = Field(
        default_factory=dict,
        description="Size measurements in bytes.",
    )


# ============================================================
# ML-KEM request models
# ============================================================

class KyberEncapsulateRequest(BaseModel):
    public_key: str = Field(
        ...,
        min_length=1,
        description="Clave pública ML-KEM codificada en Base64.",
    )

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("public_key no puede estar vacío.")
        return value


class KyberDecapsulateRequest(BaseModel):
    ciphertext: str = Field(
        ...,
        min_length=1,
        description="Ciphertext ML-KEM codificado en Base64.",
    )
    secret_key: str = Field(
        ...,
        min_length=1,
        description="Clave secreta ML-KEM codificada en Base64.",
    )

    @field_validator("ciphertext", "secret_key")
    @classmethod
    def validate_non_empty_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("El campo no puede estar vacío.")
        return value


# ============================================================
# ML-KEM response models
# ============================================================

class KyberKeypairResponse(BaseModel):
    algorithm: str = Field(
        description="ML-KEM algorithm used to generate the keypair.",
    )
    public_key: str = Field(
        description="ML-KEM public key encoded in Base64.",
    )
    secret_key: str = Field(
        description="ML-KEM secret key encoded in Base64.",
    )
    measurements: Dict[str, float] = Field(
        default_factory=dict,
        description="Timing measurements in milliseconds.",
    )
    sizes_bytes: Dict[str, int] = Field(
        default_factory=dict,
        description="Key size measurements in bytes.",
    )


class KyberEncapsulateResponse(BaseModel):
    algorithm: str = Field(
        description="ML-KEM algorithm used for encapsulation.",
    )
    ciphertext: str = Field(
        description="ML-KEM ciphertext encoded in Base64.",
    )
    shared_secret: str = Field(
        description="Shared secret encoded in Base64.",
    )
    measurements: Dict[str, float] = Field(
        default_factory=dict,
        description="Timing measurements in milliseconds.",
    )
    sizes_bytes: Dict[str, int] = Field(
        default_factory=dict,
        description="Ciphertext and shared secret size measurements in bytes.",
    )


class KyberDecapsulateResponse(BaseModel):
    algorithm: str = Field(
        description="ML-KEM algorithm used for decapsulation.",
    )
    shared_secret: str = Field(
        description="Decapsulated shared secret encoded in Base64.",
    )
    measurements: Dict[str, float] = Field(
        default_factory=dict,
        description="Timing measurements in milliseconds.",
    )
    sizes_bytes: Dict[str, int] = Field(
        default_factory=dict,
        description="Ciphertext, secret key and shared secret size measurements in bytes.",
    )


# ============================================================
# ML-DSA request models
# ============================================================

class DilithiumSignRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        description="Mensaje en texto plano que se firmará usando UTF-8.",
    )
    secret_key: str = Field(
        ...,
        min_length=1,
        description="Clave secreta ML-DSA codificada en Base64.",
    )

    @field_validator("message", "secret_key")
    @classmethod
    def validate_non_empty_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("El campo no puede estar vacío.")
        return value


class DilithiumVerifyRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        description="Mensaje en texto plano que se verificará usando UTF-8.",
    )
    signature: str = Field(
        ...,
        min_length=1,
        description="Firma ML-DSA codificada en Base64.",
    )
    public_key: str = Field(
        ...,
        min_length=1,
        description="Clave pública ML-DSA codificada en Base64.",
    )

    @field_validator("message", "signature", "public_key")
    @classmethod
    def validate_non_empty_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("El campo no puede estar vacío.")
        return value


# ============================================================
# ML-DSA response models
# ============================================================

class DilithiumKeypairResponse(BaseModel):
    algorithm: str = Field(
        description="ML-DSA algorithm used to generate the keypair.",
    )
    public_key: str = Field(
        description="ML-DSA public key encoded in Base64.",
    )
    secret_key: str = Field(
        description="ML-DSA secret key encoded in Base64.",
    )
    measurements: Dict[str, float] = Field(
        default_factory=dict,
        description="Timing measurements in milliseconds.",
    )
    sizes_bytes: Dict[str, int] = Field(
        default_factory=dict,
        description="Key size measurements in bytes.",
    )


class DilithiumSignResponse(BaseModel):
    algorithm: str = Field(
        description="ML-DSA algorithm used for signing.",
    )
    signature: str = Field(
        description="ML-DSA signature encoded in Base64.",
    )
    measurements: Dict[str, float] = Field(
        default_factory=dict,
        description="Timing measurements in milliseconds.",
    )
    sizes_bytes: Dict[str, int] = Field(
        default_factory=dict,
        description="Message, secret key and signature size measurements in bytes.",
    )


class DilithiumVerifyResponse(BaseModel):
    algorithm: str = Field(
        description="ML-DSA algorithm used for verification.",
    )
    is_valid: bool = Field(
        description="Whether the signature is valid for the provided message and public key.",
    )
    measurements: Dict[str, float] = Field(
        default_factory=dict,
        description="Timing measurements in milliseconds.",
    )
    sizes_bytes: Dict[str, int] = Field(
        default_factory=dict,
        description="Message, public key and signature size measurements in bytes.",
    )