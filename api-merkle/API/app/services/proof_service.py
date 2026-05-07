from __future__ import annotations

from typing import Dict, List

from API.app.crypto.merkle import generate_inclusion_proof, get_merkle_root
from API.app.services.registry_service import list_entries, get_signed_root


def _build_leaf_hashes(entries: List[Dict]) -> List[str]:
    """
    Extrae directamente los hashes de hoja ya persistidos en el sistema.
    """
    return [entry["leaf_hash"] for entry in entries]


def find_entry_by_identity(identity: str) -> Dict:
    """
    Busca una entrada por identidad exacta.

    Lanza ValueError si no existe.
    """
    entries = list_entries()

    for entry in entries:
        if entry["identity"] == identity:
            return entry

    raise ValueError(f"No existe ninguna entrada para la identidad '{identity}'.")


def get_inclusion_proof_for_identity(identity: str) -> Dict:
    """
    Devuelve la prueba de inclusión de una identidad junto con:
    - la raíz del árbol
    - la firma de la raíz
    - la versión del árbol
    - metadatos asociados

    Importante:
    La prueba se calcula sobre el estado actual de las entradas activas y se
    acompaña de la última raíz firmada persistida.
    """
    entries = list_entries()

    if not entries:
        raise ValueError("El registro está vacío.")

    matching_index = None
    matching_entry = None

    for index, entry in enumerate(entries):
        if entry["identity"] == identity:
            matching_index = index
            matching_entry = entry
            break

    if matching_index is None or matching_entry is None:
        raise ValueError(f"No existe ninguna entrada para la identidad '{identity}'.")

    # Construcción de la prueba sobre el estado actual del árbol
    leaf_hashes = _build_leaf_hashes(entries)
    proof = generate_inclusion_proof(leaf_hashes, matching_index)

    # Recuperamos la última raíz firmada persistida
    signed_root = get_signed_root()

    # Comprobación defensiva:
    # verificamos que la raíz persistida coincide con la raíz reconstruida a partir
    # de las entradas activas actuales.
    current_root = get_merkle_root(leaf_hashes)

    if current_root != signed_root["root_hash"]:
        raise ValueError(
            "Inconsistencia detectada: la raíz persistida no coincide con la raíz reconstruida."
        )

    return {
        "identity": identity,
        "entry": matching_entry,
        "proof": proof,
        "tree_version": signed_root["tree_version"],
        "root_hash": signed_root["root_hash"],
        "signature_b64": signed_root["signature_b64"],
        "public_key_b64": signed_root["public_key_b64"],
        "algorithm": signed_root["algorithm"],
        "tree_size": signed_root["tree_size"],
        "generated_at": signed_root["generated_at"],
    }