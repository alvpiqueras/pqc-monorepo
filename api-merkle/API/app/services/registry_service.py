from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List, Tuple, cast

from API.app.crypto.merkle import get_merkle_root, hash_leaf
from API.app.crypto.signatures import (
    generate_signature_keypair,
    sign_root_hash,
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


# Claves del operador del registro (en memoria para la PoC)
_OPERATOR_KEYS: Dict[str, str] | None = None


def _get_operator_keys() -> Dict[str, str]:
    """
    Genera una única vez las claves del operador del registro.
    Estas claves se usan para firmar la raíz de Merkle.
    """
    global _OPERATOR_KEYS

    if _OPERATOR_KEYS is None:
        _OPERATOR_KEYS = generate_signature_keypair()

    return _OPERATOR_KEYS


def _rebuild_and_store_signed_root(tree_version: int) -> Dict:
    """
    Reconstruye el árbol completo a partir de las entradas activas,
    calcula la nueva raíz, la firma y la persiste en base de datos
    con una versión explícita del árbol.
    """
    repo = _get_repository()
    entries = repo.list_entries()

    leaf_hashes = [cast(str, entry.leaf_hash) for entry in entries]

    if not leaf_hashes:
        raise ValueError(
            "No se puede reconstruir una raíz firmada sobre un registro vacío."
        )

    root_hash = get_merkle_root(leaf_hashes)
    tree_size = len(leaf_hashes)

    operator_keys = _get_operator_keys()

    signature_b64 = sign_root_hash(
        root_hash=root_hash,
        secret_key_b64=operator_keys["secret_key_b64"],
        algorithm=operator_keys["algorithm"],
    )

    saved_root = repo.save_signed_root(
        tree_version=tree_version,
        tree_size=tree_size,
        merkle_root=root_hash,
        signature=signature_b64,
        public_key=operator_keys["public_key_b64"],
    )

    return {
        "tree_version": tree_version,
        "tree_size": tree_size,
        "root_hash": cast(str, saved_root.merkle_root),
        "signature_b64": cast(str, saved_root.signature),
        "public_key_b64": cast(str, saved_root.public_key),
        "algorithm": operator_keys["algorithm"],
        "generated_at": saved_root.created_at.isoformat(),
    }


def add_entry(entry_data: Dict) -> Dict:
    """
    Añade una nueva entrada al registro, persiste su hash de hoja
    y actualiza la raíz firmada del árbol de Merkle.
    """
    repo = _get_repository()

    valid_from = entry_data.get("valid_from")
    valid_until = entry_data.get("valid_until")

    if isinstance(valid_from, datetime):
        valid_from = valid_from.isoformat()

    if isinstance(valid_until, datetime):
        valid_until = valid_until.isoformat()

    # La nueva entrada provoca un nuevo estado del árbol
    next_tree_version = repo.get_latest_tree_version() + 1

    new_entry = {
        "identity": entry_data["identity"],
        "public_key_b64": entry_data["public_key_b64"],
        "metadata": entry_data.get("metadata", {}),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tree_version": next_tree_version,
    }

    # Datos que forman parte de la afirmación registrada
    # y, por tanto, del hash de hoja
    leaf_data = {
        "identity": new_entry["identity"],
        "public_key_b64": new_entry["public_key_b64"],
        "metadata": new_entry["metadata"],
        "valid_from": new_entry["valid_from"],
        "valid_until": new_entry["valid_until"],
    }

    leaf_hash = hash_leaf(leaf_data)
    new_entry["leaf_hash"] = leaf_hash

    saved_entry = repo.add_entry(
        identity=new_entry["identity"],
        public_key=new_entry["public_key_b64"],
        metadata_json=json.dumps(new_entry["metadata"]),
        valid_from=new_entry["valid_from"],
        valid_until=new_entry["valid_until"],
        leaf_hash=leaf_hash,
        tree_version=next_tree_version,
    )

    new_entry["entry_id"] = str(saved_entry.id)

    # Tras insertar una nueva entrada, regeneramos y persistimos
    # la nueva raíz firmada del registro
    _rebuild_and_store_signed_root(next_tree_version)

    return new_entry


def list_entries() -> List[Dict]:
    """
    Devuelve todas las entradas activas del registro en formato diccionario.
    """
    repo = _get_repository()
    entries = repo.list_entries()

    return [
        {
            "entry_id": str(e.id),
            "identity": e.identity,
            "public_key_b64": e.public_key,
            "metadata": json.loads(cast(str, e.metadata_json)),
            "valid_from": e.valid_from,
            "valid_until": e.valid_until,
            "leaf_hash": cast(str, e.leaf_hash),
            "created_at": e.created_at.isoformat(),
            "tree_version": cast(int, e.tree_version),
        }
        for e in entries
    ]


def list_entries_up_to_version(tree_version: int) -> List[Dict]:
    """
    Devuelve las entradas activas incluidas hasta una versión concreta del árbol.
    Esta función es especialmente útil para reconstrucciones históricas y
    para futuras pruebas de consistencia.
    """
    repo = _get_repository()
    entries = repo.list_entries_up_to_version(tree_version)

    return [
        {
            "entry_id": str(e.id),
            "identity": e.identity,
            "public_key_b64": e.public_key,
            "metadata": json.loads(cast(str, e.metadata_json)),
            "valid_from": e.valid_from,
            "valid_until": e.valid_until,
            "leaf_hash": cast(str, e.leaf_hash),
            "created_at": e.created_at.isoformat(),
            "tree_version": cast(int, e.tree_version),
        }
        for e in entries
    ]


def compute_tree_and_root() -> Tuple[str, List[str]]:
    """
    Reconstruye el árbol a partir de las entradas activas y devuelve:
    - la raíz de Merkle
    - la lista de hashes de hoja
    """
    repo = _get_repository()
    entries = repo.list_entries()

    leaf_hashes = [cast(str, entry.leaf_hash) for entry in entries]
    root_hash = get_merkle_root(leaf_hashes)

    return root_hash, leaf_hashes


def compute_tree_and_root_up_to_version(tree_version: int) -> Tuple[str, List[str]]:
    """
    Reconstruye el árbol utilizando únicamente las entradas activas
    incluidas hasta la versión indicada.
    """
    repo = _get_repository()
    entries = repo.list_entries_up_to_version(tree_version)

    leaf_hashes = [cast(str, entry.leaf_hash) for entry in entries]
    root_hash = get_merkle_root(leaf_hashes)

    return root_hash, leaf_hashes


def get_signed_root() -> Dict:
    """
    Devuelve la última raíz firmada persistida del registro.

    Si todavía no existe ninguna raíz almacenada, se reconstruye,
    se firma, se persiste y se devuelve como versión 1.
    """
    repo = _get_repository()

    latest_root = repo.get_latest_root()

    if latest_root is not None:
        return {
            "tree_version": cast(int, latest_root.tree_version),
            "tree_size": cast(int, latest_root.tree_size),
            "root_hash": cast(str, latest_root.merkle_root),
            "signature_b64": cast(str, latest_root.signature),
            "public_key_b64": cast(str, latest_root.public_key),
            "algorithm": _get_operator_keys()["algorithm"],
            "generated_at": latest_root.created_at.isoformat(),
        }

    return _rebuild_and_store_signed_root(tree_version=1)