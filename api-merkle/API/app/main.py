from __future__ import annotations

from fastapi import FastAPI, HTTPException

from API.app.crypto.merkle import hash_leaf, verify_inclusion_proof
from API.app.crypto.signatures import verify_root_hash_signature
from API.app.db.database import engine
from API.app.db.models import Base
from API.app.models.schemas import (
    ConsistencyProofRequest,
    ConsistencyProofResponse,
    ProofRequest,
    ProofResponse,
    RegistryEntryCreate,
    RegistryEntryResponse,
    RegistryEntryStored,
    RegistryListResponse,
    RootResponse,
    VerifyConsistencyProofRequest,
    VerifyConsistencyProofResponse,
    VerifyProofRequest,
    VerifyProofResponse,
    VerifyRootSignatureRequest,
    VerifyRootSignatureResponse,
)
from API.app.services.consistency_service import (
    get_consistency_proof_between_versions,
    verify_consistency_proof_payload,
)
from API.app.services.proof_service import get_inclusion_proof_for_identity
from API.app.services.registry_service import add_entry, get_signed_root, list_entries

app = FastAPI(
    title="PQC Certificate Registry API",
    description="PoC de registro de identidades y claves públicas con árbol de Merkle y firma PQC de la raíz.",
    version="0.3.0",
)

# Creación automática de tablas al arrancar la aplicación.
# En una fase posterior esto podría sustituirse por migraciones formales.
Base.metadata.create_all(bind=engine)


@app.get("/")
def healthcheck() -> dict:
    """
    Endpoint básico de comprobación de servicio.
    """
    return {
        "message": "PQC Certificate Registry API is running"
    }


@app.post("/registry/entries", response_model=RegistryEntryResponse)
def create_registry_entry(payload: RegistryEntryCreate) -> RegistryEntryResponse:
    """
    Registra una nueva afirmación identidad ↔ clave pública
    y actualiza el estado autenticado del registro.
    """
    try:
        entry = add_entry(payload.model_dump(mode="json"))

        entry_stored = RegistryEntryStored(
            entry_id=entry["entry_id"],
            identity=entry["identity"],
            public_key_b64=entry["public_key_b64"],
            metadata=entry.get("metadata", {}),
            valid_from=entry.get("valid_from"),
            valid_until=entry.get("valid_until"),
            created_at=entry["created_at"],
            leaf_hash=entry.get("leaf_hash", ""),
            tree_version=entry["tree_version"],
        )

        return RegistryEntryResponse(
            message="Entrada registrada correctamente.",
            entry=entry_stored,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/registry/entries", response_model=RegistryListResponse)
def get_registry_entries() -> RegistryListResponse:
    """
    Devuelve todas las entradas activas del registro.
    """
    try:
        raw_entries = list_entries()

        entries = [
            RegistryEntryStored(
                entry_id=entry["entry_id"],
                identity=entry["identity"],
                public_key_b64=entry["public_key_b64"],
                metadata=entry.get("metadata", {}),
                valid_from=entry.get("valid_from"),
                valid_until=entry.get("valid_until"),
                created_at=entry["created_at"],
                leaf_hash=entry.get("leaf_hash", ""),
                tree_version=entry["tree_version"],
            )
            for entry in raw_entries
        ]

        return RegistryListResponse(
            total=len(entries),
            entries=entries,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/registry/root", response_model=RootResponse)
def get_registry_root() -> RootResponse:
    """
    Devuelve la última raíz firmada persistida del árbol de Merkle.
    """
    try:
        root_data = get_signed_root()

        return RootResponse(
            tree_version=root_data["tree_version"],
            root_hash=root_data["root_hash"],
            signature_b64=root_data["signature_b64"],
            public_key_b64=root_data["public_key_b64"],
            algorithm=root_data["algorithm"],
            tree_size=root_data["tree_size"],
            generated_at=root_data["generated_at"],
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/registry/proof", response_model=ProofResponse)
def get_registry_proof(payload: ProofRequest) -> ProofResponse:
    """
    Devuelve la prueba de inclusión para una identidad concreta,
    junto con la raíz firmada correspondiente.
    """
    try:
        proof_data = get_inclusion_proof_for_identity(payload.identity)

        return ProofResponse(
            identity=proof_data["identity"],
            entry=proof_data["entry"],
            proof=proof_data["proof"],
            tree_version=proof_data["tree_version"],
            root_hash=proof_data["root_hash"],
            signature_b64=proof_data["signature_b64"],
            public_key_b64=proof_data["public_key_b64"],
            algorithm=proof_data["algorithm"],
            tree_size=proof_data["tree_size"],
            generated_at=proof_data["generated_at"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/registry/verify-proof", response_model=VerifyProofResponse)
def verify_registry_proof(payload: VerifyProofRequest) -> VerifyProofResponse:
    """
    Verifica localmente una prueba de inclusión frente a una raíz dada.
    """
    try:
        entry_json = payload.entry.model_dump(mode="json")

        leaf_data = {
            "identity": entry_json["identity"],
            "public_key_b64": entry_json["public_key_b64"],
            "metadata": entry_json["metadata"],
            "valid_from": entry_json["valid_from"],
            "valid_until": entry_json["valid_until"],
        }

        leaf_hash = hash_leaf(leaf_data)

        valid, computed_root = verify_inclusion_proof(
            leaf_hash=leaf_hash,
            proof=[step.model_dump() for step in payload.proof],
            expected_root=payload.root_hash,
        )

        return VerifyProofResponse(
            valid=valid,
            computed_root=computed_root,
            expected_root=payload.root_hash,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/registry/verify-root-signature", response_model=VerifyRootSignatureResponse)
def verify_registry_root_signature(
    payload: VerifyRootSignatureRequest,
) -> VerifyRootSignatureResponse:
    """
    Verifica la firma post-cuántica asociada a una raíz de Merkle.
    """
    try:
        valid = verify_root_hash_signature(
            root_hash=payload.root_hash,
            signature_b64=payload.signature_b64,
            public_key_b64=payload.public_key_b64,
            algorithm=payload.algorithm,
        )

        return VerifyRootSignatureResponse(valid=valid)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/registry/consistency-proof", response_model=ConsistencyProofResponse)
def get_registry_consistency_proof(
    payload: ConsistencyProofRequest,
) -> ConsistencyProofResponse:
    """
    Devuelve una prueba de consistencia entre dos versiones del árbol.

    La prueba permite verificar que la versión nueva representa una
    extensión append-only de la versión antigua.
    """
    try:
        proof_data = get_consistency_proof_between_versions(
            old_tree_version=payload.old_tree_version,
            new_tree_version=payload.new_tree_version,
        )

        return ConsistencyProofResponse(
            old_tree_version=proof_data["old_tree_version"],
            new_tree_version=proof_data["new_tree_version"],
            old_tree_size=proof_data["old_tree_size"],
            new_tree_size=proof_data["new_tree_size"],
            old_root_hash=proof_data["old_root_hash"],
            new_root_hash=proof_data["new_root_hash"],
            old_leaf_hashes=proof_data["old_leaf_hashes"],
            appended_leaf_hashes=proof_data["appended_leaf_hashes"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post(
    "/registry/verify-consistency-proof",
    response_model=VerifyConsistencyProofResponse,
)
def verify_registry_consistency_proof(
    payload: VerifyConsistencyProofRequest,
) -> VerifyConsistencyProofResponse:
    """
    Verifica localmente una prueba de consistencia entre dos versiones del árbol.
    """
    try:
        verification_result = verify_consistency_proof_payload(
            payload.model_dump(mode="json")
        )

        return VerifyConsistencyProofResponse(
            valid=verification_result["valid"],
            reconstructed_old_root=verification_result["reconstructed_old_root"],
            reconstructed_new_root=verification_result["reconstructed_new_root"],
            expected_old_root=verification_result["expected_old_root"],
            expected_new_root=verification_result["expected_new_root"],
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc