from __future__ import annotations

from typing import Dict, List, Tuple

from API.app.crypto.merkle import get_merkle_root


def _validate_append_only_prefix(
    old_leaf_hashes: List[str],
    new_leaf_hashes: List[str],
) -> None:
    """
    Comprueba que el conjunto antiguo de hojas es un prefijo exacto
    del conjunto nuevo de hojas.

    Esta condición modela el comportamiento append-only del registro:
    una versión más reciente solo puede añadir hojas al final, pero
    no modificar, eliminar ni reordenar las ya existentes.
    """
    if len(old_leaf_hashes) > len(new_leaf_hashes):
        raise ValueError(
            "La versión antigua no puede tener más hojas que la versión nueva."
        )

    prefix = new_leaf_hashes[: len(old_leaf_hashes)]

    if prefix != old_leaf_hashes:
        raise ValueError(
            "Las hojas de la versión antigua no forman un prefijo de la versión nueva."
        )


def generate_consistency_proof(
    old_leaf_hashes: List[str],
    new_leaf_hashes: List[str],
) -> Dict:
    """
    Genera una prueba de consistencia intermedia entre dos versiones del árbol.

    Esta implementación no busca todavía la prueba mínima optimizada
    estilo transparency log formal, sino una prueba sólida y clara
    para una PoC académica.

    La prueba demuestra que:
    - el árbol nuevo contiene todas las hojas del árbol antiguo,
    - y que las hojas antiguas aparecen como prefijo exacto del nuevo.

    Devuelve:
    - tamaño del árbol antiguo,
    - tamaño del árbol nuevo,
    - raíz antigua,
    - raíz nueva,
    - prefijo antiguo,
    - sufijo añadido.
    """
    if not old_leaf_hashes:
        raise ValueError("La versión antigua no puede ser vacía.")

    if not new_leaf_hashes:
        raise ValueError("La versión nueva no puede ser vacía.")

    _validate_append_only_prefix(old_leaf_hashes, new_leaf_hashes)

    old_tree_size = len(old_leaf_hashes)
    new_tree_size = len(new_leaf_hashes)

    old_root_hash = get_merkle_root(old_leaf_hashes)
    new_root_hash = get_merkle_root(new_leaf_hashes)

    appended_leaf_hashes = new_leaf_hashes[old_tree_size:]

    return {
        "old_tree_size": old_tree_size,
        "new_tree_size": new_tree_size,
        "old_root_hash": old_root_hash,
        "new_root_hash": new_root_hash,
        "old_leaf_hashes": old_leaf_hashes,
        "appended_leaf_hashes": appended_leaf_hashes,
    }


def verify_consistency_proof(
    old_root_hash: str,
    new_root_hash: str,
    old_tree_size: int,
    new_tree_size: int,
    old_leaf_hashes: List[str],
    appended_leaf_hashes: List[str],
) -> Tuple[bool, str, str]:
    """
    Verifica una prueba de consistencia intermedia.

    La verificación reconstruye:
    - el árbol antiguo a partir de old_leaf_hashes
    - el árbol nuevo a partir de old_leaf_hashes + appended_leaf_hashes

    y comprueba que:
    - la raíz reconstruida antigua coincide con old_root_hash
    - la raíz reconstruida nueva coincide con new_root_hash
    - el tamaño del árbol antiguo y nuevo coincide con lo declarado

    Devuelve:
    - resultado booleano
    - raíz antigua reconstruida
    - raíz nueva reconstruida
    """
    if old_tree_size <= 0:
        raise ValueError("old_tree_size debe ser mayor que cero.")

    if new_tree_size <= 0:
        raise ValueError("new_tree_size debe ser mayor que cero.")

    if old_tree_size > new_tree_size:
        raise ValueError(
            "old_tree_size no puede ser mayor que new_tree_size."
        )

    if len(old_leaf_hashes) != old_tree_size:
        raise ValueError(
            "El número de old_leaf_hashes no coincide con old_tree_size."
        )

    new_leaf_hashes = old_leaf_hashes + appended_leaf_hashes

    if len(new_leaf_hashes) != new_tree_size:
        raise ValueError(
            "El número total de hojas reconstruidas no coincide con new_tree_size."
        )

    reconstructed_old_root = get_merkle_root(old_leaf_hashes)
    reconstructed_new_root = get_merkle_root(new_leaf_hashes)

    valid = (
        reconstructed_old_root == old_root_hash
        and reconstructed_new_root == new_root_hash
    )

    return valid, reconstructed_old_root, reconstructed_new_root