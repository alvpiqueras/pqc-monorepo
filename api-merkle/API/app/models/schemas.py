from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class RegistryEntryCreate(BaseModel):
    """
    Modelo de entrada para registrar una identidad en el registro.
    """
    identity: str = Field(..., min_length=1, max_length=256, description="Identidad única")
    public_key_b64: str = Field(..., min_length=1, description="Clave pública en Base64")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadatos asociados")
    valid_from: Optional[datetime] = Field(default=None, description="Inicio de vigencia")
    valid_until: Optional[datetime] = Field(default=None, description="Fin de vigencia")


class RegistryEntryStored(BaseModel):
    """
    Modelo de una entrada ya almacenada en el registro.
    """
    entry_id: str = Field(..., description="Identificador único de la entrada")
    identity: str = Field(..., description="Identidad registrada")
    public_key_b64: str = Field(..., description="Clave pública en Base64")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadatos asociados")
    valid_from: Optional[datetime] = Field(default=None, description="Inicio de vigencia")
    valid_until: Optional[datetime] = Field(default=None, description="Fin de vigencia")
    created_at: datetime = Field(..., description="Fecha de creación de la entrada")
    leaf_hash: str = Field(..., description="Hash de la hoja correspondiente en el árbol Merkle")
    tree_version: int = Field(..., description="Versión del árbol en la que se registró la entrada")


class RegistryEntryResponse(BaseModel):
    """
    Respuesta homogénea al registrar una entrada.
    """
    success: bool = True
    message: str
    entry: RegistryEntryStored


class RegistryListResponse(BaseModel):
    """
    Respuesta con todas las entradas del registro.
    """
    success: bool = True
    total: int
    entries: List[RegistryEntryStored]


class MerkleProofStep(BaseModel):
    """
    Paso de la prueba de inclusión.
    direction:
      - 'left'  => el hash hermano está a la izquierda
      - 'right' => el hash hermano está a la derecha
    """
    sibling_hash: str = Field(..., description="Hash del nodo hermano")
    direction: Literal["left", "right"] = Field(..., description="Posición del hermano")


class RootResponse(BaseModel):
    """
    Información de la raíz actual del árbol y su firma PQC.
    """
    success: bool = True
    tree_version: int = Field(..., description="Versión del estado autenticado del árbol")
    root_hash: str = Field(..., description="Raíz actual del árbol de Merkle")
    signature_b64: str = Field(..., description="Firma PQC de la raíz en Base64")
    public_key_b64: str = Field(..., description="Clave pública del operador del registro")
    algorithm: str = Field(..., description="Algoritmo de firma usado")
    tree_size: int = Field(..., description="Número de hojas del árbol")
    generated_at: datetime = Field(..., description="Fecha de generación de la raíz firmada")


class ProofRequest(BaseModel):
    """
    Petición de prueba de inclusión para una identidad concreta.
    """
    identity: str = Field(..., min_length=1, max_length=256, description="Identidad a buscar")


class ProofResponse(BaseModel):
    """
    Respuesta con la prueba de inclusión y la raíz firmada.
    """
    success: bool = True
    identity: str
    entry: RegistryEntryStored
    proof: List[MerkleProofStep]
    tree_version: int
    root_hash: str
    signature_b64: str
    public_key_b64: str
    algorithm: str
    tree_size: int
    generated_at: datetime


class VerifyProofRequest(BaseModel):
    """
    Petición para verificar una prueba de inclusión.
    """
    entry: RegistryEntryStored
    proof: List[MerkleProofStep]
    root_hash: str


class VerifyProofResponse(BaseModel):
    """
    Resultado de la verificación de la prueba de inclusión.
    """
    success: bool = True
    valid: bool
    computed_root: str
    expected_root: str


class VerifyRootSignatureRequest(BaseModel):
    """
    Petición para verificar la firma PQC de la raíz.
    """
    root_hash: str
    signature_b64: str
    public_key_b64: str
    algorithm: str = Field(default="ML-DSA-65")


class VerifyRootSignatureResponse(BaseModel):
    """
    Resultado de la verificación de la firma de la raíz.
    """
    success: bool = True
    valid: bool

class ConsistencyProofRequest(BaseModel):
    """
    Petición de prueba de consistencia entre dos versiones del árbol.
    """
    old_tree_version: int = Field(..., gt=0, description="Versión antigua del árbol")
    new_tree_version: int = Field(..., gt=0, description="Versión nueva del árbol")


class ConsistencyProofResponse(BaseModel):
    """
    Respuesta con la prueba de consistencia entre dos versiones del árbol.
    """
    success: bool = True
    old_tree_version: int
    new_tree_version: int
    old_tree_size: int
    new_tree_size: int
    old_root_hash: str
    new_root_hash: str
    old_leaf_hashes: List[str]
    appended_leaf_hashes: List[str]


class VerifyConsistencyProofRequest(BaseModel):
    """
    Petición para verificar una prueba de consistencia.
    """
    old_root_hash: str
    new_root_hash: str
    old_tree_size: int = Field(..., gt=0)
    new_tree_size: int = Field(..., gt=0)
    old_leaf_hashes: List[str]
    appended_leaf_hashes: List[str]


class VerifyConsistencyProofResponse(BaseModel):
    """
    Resultado de la verificación de una prueba de consistencia.
    """
    success: bool = True
    valid: bool
    reconstructed_old_root: str
    reconstructed_new_root: str
    expected_old_root: str
    expected_new_root: str


class ErrorResponse(BaseModel):
    """
    Modelo de error homogéneo.
    """
    success: bool = False
    message: str