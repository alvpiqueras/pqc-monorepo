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

from API.app.models.metrics_models import (
    MerkleMetricsDemoRequest,
    MerkleMetricsDemoResponse,
)
from API.app.services.metrics_service import run_merkle_metrics_demo


app = FastAPI(
    title="PQC Certificate Registry API",
    description=(
        "PoC de registro verificable de identidades y claves públicas usando "
        "árboles de Merkle y firma post-cuántica de la raíz."
    ),
    version="0.4.0",
)

# Creación automática de tablas al arrancar la aplicación.
# En una fase posterior esto podría sustituirse por migraciones formales.
Base.metadata.create_all(bind=engine)


@app.get(
    "/",
    tags=["Merkle Registry - Overview"],
)
def healthcheck() -> dict:
    """
    Basic service healthcheck.
    """
    return {
        "message": "PQC Certificate Registry API is running"
    }


@app.get(
    "/registry/info",
    tags=["Merkle Registry - Overview"],
)
def registry_info() -> dict:
    """
    Explain the purpose of the Merkle-based certificate registry.

    This endpoint provides a high-level description of the registry/log model
    used as an alternative or complement to traditional X.509 certificate
    consumption.
    """

    return {
        "service_name": "api-merkle",
        "title": "Merkle-based PQC Certificate Registry",
        "summary": (
            "This API implements a verifiable registry of identity-to-public-key "
            "assertions using a Merkle tree. Each registered identity becomes a "
            "leaf in the tree, and the authenticated state of the registry is "
            "represented by a signed Merkle root."
        ),
        "problem_addressed": (
            "Post-quantum X.509 certificates may become larger due to PQC public "
            "keys and signatures. A Merkle-based registry explores an alternative "
            "trust model where clients can verify that an identity and public key "
            "belong to an authenticated registry state without relying only on "
            "transporting full certificate chains in every interaction."
        ),
        "trust_model": {
            "type": "verifiable-registry",
            "operator": (
                "A registry operator maintains the append-only set of identity "
                "assertions and signs the current Merkle root."
            ),
            "client": (
                "A verifier checks inclusion proofs, consistency proofs and the "
                "signature over the Merkle root."
            ),
        },
        "main_concepts": {
            "registry_entry": (
                "An assertion binding an identity to a public key and optional "
                "metadata such as validity information."
            ),
            "leaf_hash": (
                "Deterministic hash of the registry entry. It is used as a leaf "
                "inside the Merkle tree."
            ),
            "merkle_root": (
                "Compact cryptographic commitment to the full registry state at "
                "a given tree version."
            ),
            "root_signature": (
                "Post-quantum signature over the Merkle root, allowing clients to "
                "authenticate the published registry state."
            ),
            "inclusion_proof": (
                "Proof that a specific identity entry belongs to a given Merkle "
                "root."
            ),
            "consistency_proof": (
                "Proof that a newer registry version extends an older one in an "
                "append-only way."
            ),
        },
        "typical_flow": [
            "A new identity and public key are registered.",
            "The registry recomputes the Merkle tree.",
            "The new Merkle root is signed with a PQC signature key.",
            "A client requests an inclusion proof for an identity.",
            "The client verifies the inclusion proof against the signed root.",
            "Optionally, the client verifies consistency between registry versions.",
        ],
        "relationship_with_x509": (
            "This API does not replace X.509 in production. It is an academic "
            "prototype that explores how registry/log-based trust models could "
            "complement or partially reduce repeated certificate material "
            "transmission in PQC-heavy environments."
        ),
        "what_this_api_demonstrates": [
            "Identity-to-key registration.",
            "Merkle root generation.",
            "PQC signature of authenticated registry state.",
            "Inclusion proof generation and verification.",
            "Append-only consistency proof generation and verification.",
        ],
        "scope_note": (
            "This is a proof of concept for the TFM laboratory. It is not a "
            "production certificate transparency log, CA system or public PKI."
        ),
    }


@app.post(
    "/registry/entries",
    response_model=RegistryEntryResponse,
    tags=["Entries"],
)
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


@app.get(
    "/registry/entries",
    response_model=RegistryListResponse,
    tags=["Entries"],
)
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


@app.get(
    "/registry/root",
    response_model=RootResponse,
    tags=["Root"],
)
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


@app.post(
    "/registry/verify-root-signature",
    response_model=VerifyRootSignatureResponse,
    tags=["Root"],
)
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


@app.post(
    "/registry/proof",
    response_model=ProofResponse,
    tags=["Inclusion Proofs"],
)
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


@app.post(
    "/registry/verify-proof",
    response_model=VerifyProofResponse,
    tags=["Inclusion Proofs"],
)
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


@app.post(
    "/registry/consistency-proof",
    response_model=ConsistencyProofResponse,
    tags=["Consistency Proofs"],
)
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
    tags=["Consistency Proofs"],
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
    

@app.post(
    "/registry/metrics/demo",
    response_model=MerkleMetricsDemoResponse,
    tags=["Metrics"],
)
def registry_metrics_demo(
    payload: MerkleMetricsDemoRequest,
) -> MerkleMetricsDemoResponse:
    """
    Runs an in-memory metrics demo for the Merkle registry.

    This endpoint generates synthetic registry entries, builds a Merkle tree,
    generates and verifies an inclusion proof, checks a simple append-only
    consistency payload and signs/verifies the Merkle root with ML-DSA.

    It does not modify the persistent registry database.
    """
    try:
        return MerkleMetricsDemoResponse(
            **run_merkle_metrics_demo(payload)
        )

    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc