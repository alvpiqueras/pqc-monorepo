from pydantic import BaseModel, Field, field_validator


class KyberEncapsulateRequest(BaseModel):
    public_key: str = Field(
        ...,
        min_length=1,
        description="Clave pública ML-KEM codificada en Base64."
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
        description="Ciphertext ML-KEM codificado en Base64."
    )
    secret_key: str = Field(
        ...,
        min_length=1,
        description="Clave secreta ML-KEM codificada en Base64."
    )

    @field_validator("ciphertext", "secret_key")
    @classmethod
    def validate_non_empty_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("El campo no puede estar vacío.")
        return value


class DilithiumSignRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        description="Mensaje en texto plano que se firmará usando UTF-8."
    )
    secret_key: str = Field(
        ...,
        min_length=1,
        description="Clave secreta ML-DSA codificada en Base64."
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
        description="Mensaje en texto plano que se verificará usando UTF-8."
    )
    signature: str = Field(
        ...,
        min_length=1,
        description="Firma ML-DSA codificada en Base64."
    )
    public_key: str = Field(
        ...,
        min_length=1,
        description="Clave pública ML-DSA codificada en Base64."
    )

    @field_validator("message", "signature", "public_key")
    @classmethod
    def validate_non_empty_fields(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("El campo no puede estar vacío.")
        return value