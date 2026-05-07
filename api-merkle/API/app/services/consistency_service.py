from __future__ import annotations

from typing import Dict

from API.app.crypto.consistency import (
    generate_consistency_proof,
    verify_consistency_proof,
)
from API.app.services.registry_service import (
    compute_tree_and_root_up_to_version,
)
from API.app.db.database import SessionLocal
from API.app.repositories.registry_repository import SqliteRegistryRepository


def _get_repository() -> SqliteRegistryRepository:
    """
    Crea un repositorio asociado a una nueva sesión de base de datos.

    Nota:
    En esta fase de la PoC la sesión no se cierra explícitamente.
    Más adelante convendrá integrar gestión de sesión con dependencias de FastAPI.
    """
    db = SessionLocal()
    return SqliteRegistryRepository(db)


def get_consistency_proof_between_versions(
    old_tree_version: int,
    new_tree_version: int,
) -> Dict:
    """
    Genera una prueba de consistencia entre dos versiones del árbol.

    La prueba demuestra que la versión nueva representa una extensión
    append-only de la versión antigua.

    Validaciones realizadas:
    - ambas versiones deben existir
    - la versión nueva debe ser estrictamente posterior a la antigua
    - la raíz reconstruida para cada versión debe coincidir con la raíz
      firmada persistida en base de datos
    """
    if old_tree_version <= 0 or new_tree_version <= 0:
        raise ValueError("Las versiones del árbol deben ser mayores que cero.")

    if old_tree_version >= new_tree_version:
        raise ValueError(
            "La versión nueva debe ser estrictamente mayor que la versión antigua."
        )

    repo = _get_repository()

    old_signed_root = repo.get_root_by_version(old_tree_version)
    new_signed_root = repo.get_root_by_version(new_tree_version)

    if old_signed_root is None:
        raise ValueError(
            f"No existe ninguna raíz firmada para la versión {old_tree_version}."
        )

    if new_signed_root is None:
        raise ValueError(
            f"No existe ninguna raíz firmada para la versión {new_tree_version}."
        )

    old_root_hash, old_leaf_hashes = compute_tree_and_root_up_to_version(old_tree_version)
    new_root_hash, new_leaf_hashes = compute_tree_and_root_up_to_version(new_tree_version)

    # Comprobación defensiva de consistencia entre lo reconstruido y lo persistido
    if old_root_hash != old_signed_root.merkle_root:
        raise ValueError(
            "Inconsistencia detectada en la versión antigua: la raíz reconstruida "
            "no coincide con la raíz firmada persistida."
        )

    if new_root_hash != new_signed_root.merkle_root:
        raise ValueError(
            "Inconsistencia detectada en la versión nueva: la raíz reconstruida "
            "no coincide con la raíz firmada persistida."
        )

    proof = generate_consistency_proof(
        old_leaf_hashes=old_leaf_hashes,
        new_leaf_hashes=new_leaf_hashes,
    )

    return {
        "old_tree_version": old_tree_version,
        "new_tree_version": new_tree_version,
        "old_tree_size": proof["old_tree_size"],
        "new_tree_size": proof["new_tree_size"],
        "old_root_hash": proof["old_root_hash"],
        "new_root_hash": proof["new_root_hash"],
        "old_leaf_hashes": proof["old_leaf_hashes"],
        "appended_leaf_hashes": proof["appended_leaf_hashes"],
    }


def verify_consistency_proof_payload(payload: Dict) -> Dict:
    """
    Verifica una prueba de consistencia ya serializada en forma de diccionario.

    Se espera que el payload contenga:
    - old_root_hash
    - new_root_hash
    - old_tree_size
    - new_tree_size
    - old_leaf_hashes
    - appended_leaf_hashes
    """
    valid, reconstructed_old_root, reconstructed_new_root = verify_consistency_proof(
        old_root_hash=payload["old_root_hash"],
        new_root_hash=payload["new_root_hash"],
        old_tree_size=payload["old_tree_size"],
        new_tree_size=payload["new_tree_size"],
        old_leaf_hashes=payload["old_leaf_hashes"],
        appended_leaf_hashes=payload["appended_leaf_hashes"],
    )

    return {
        "valid": valid,
        "reconstructed_old_root": reconstructed_old_root,
        "reconstructed_new_root": reconstructed_new_root,
        "expected_old_root": payload["old_root_hash"],
        "expected_new_root": payload["new_root_hash"],
    }