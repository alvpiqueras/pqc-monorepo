from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Tuple


def _normalize_value(value: Any) -> Any:
    """
    Normaliza valores para serialización determinista.

    - datetime -> ISO 8601
    - dict -> normaliza recursivamente
    - list -> normaliza recursivamente
    - resto -> se devuelve tal cual
    """
    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {key: _normalize_value(value[key]) for key in sorted(value.keys())}

    if isinstance(value, list):
        return [_normalize_value(item) for item in value]

    return value


def serialize_leaf_data(entry: Dict[str, Any]) -> str:
    """
    Serializa una entrada de registro de forma determinista para poder hashearla.

    Es importante que el mismo contenido produzca siempre exactamente el mismo string,
    independientemente del orden original de las claves del diccionario.
    """
    normalized_entry = _normalize_value(entry)
    return json.dumps(normalized_entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    """
    Devuelve el SHA-256 en hexadecimal de los bytes de entrada.
    """
    return hashlib.sha256(data).hexdigest()


def hash_leaf(entry: Dict[str, Any]) -> str:
    """
    Calcula el hash de una hoja del árbol Merkle.

    Se usa domain separation:
    - prefix 'leaf:' para distinguir hojas de nodos internos.
    """
    serialized = serialize_leaf_data(entry)
    return sha256_hex(f"leaf:{serialized}".encode("utf-8"))


def hash_internal_node(left_hash: str, right_hash: str) -> str:
    """
    Calcula el hash de un nodo interno a partir de dos hijos.

    Se usa domain separation:
    - prefix 'node:' para distinguir nodos internos de hojas.
    """
    combined = f"node:{left_hash}:{right_hash}"
    return sha256_hex(combined.encode("utf-8"))


def build_merkle_tree(leaf_hashes: List[str]) -> List[List[str]]:
    """
    Construye el árbol de Merkle completo a partir de una lista de hashes de hojas.

    Devuelve una lista de niveles:
    - tree[0] = hojas
    - tree[-1][0] = raíz

    Regla para número impar de nodos:
    - se duplica el último hash del nivel.
    """
    if not leaf_hashes:
        return []

    tree: List[List[str]] = [leaf_hashes[:]]
    current_level = leaf_hashes[:]

    while len(current_level) > 1:
        next_level: List[str] = []

        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
            parent = hash_internal_node(left, right)
            next_level.append(parent)

        tree.append(next_level)
        current_level = next_level

    return tree


def get_merkle_root(leaf_hashes: List[str]) -> str:
    """
    Calcula la raíz del árbol de Merkle a partir de una lista de hashes de hojas.

    Si no hay hojas, devuelve cadena vacía.
    """
    tree = build_merkle_tree(leaf_hashes)
    if not tree:
        return ""
    return tree[-1][0]


def generate_inclusion_proof(leaf_hashes: List[str], index: int) -> List[Dict[str, str]]:
    """
    Genera la prueba de inclusión para la hoja en la posición 'index'.

    Devuelve una lista de pasos, donde cada paso tiene:
    - sibling_hash
    - direction: 'left' o 'right'

    direction indica dónde estaba el hash hermano respecto al hash actual.
    """
    if not leaf_hashes:
        raise ValueError("No se puede generar una prueba sobre un árbol vacío.")

    if index < 0 or index >= len(leaf_hashes):
        raise IndexError("Índice de hoja fuera de rango.")

    tree = build_merkle_tree(leaf_hashes)
    proof: List[Dict[str, str]] = []
    current_index = index

    for level in tree[:-1]:
        is_right_node = current_index % 2 == 1

        if is_right_node:
            sibling_index = current_index - 1
            direction = "left"
        else:
            sibling_index = current_index + 1
            direction = "right"

        if sibling_index >= len(level):
            sibling_index = current_index

        proof.append(
            {
                "sibling_hash": level[sibling_index],
                "direction": direction,
            }
        )

        current_index //= 2

    return proof


def verify_inclusion_proof(leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> Tuple[bool, str]:
    """
    Verifica una prueba de inclusión.

    Parámetros:
    - leaf_hash: hash de la hoja a verificar
    - proof: lista de pasos con sibling_hash y direction
    - expected_root: raíz que se espera obtener

    Devuelve:
    - bool indicando si la prueba es válida
    - computed_root calculada
    """
    current_hash = leaf_hash

    for step in proof:
        sibling_hash = step["sibling_hash"]
        direction = step["direction"]

        if direction == "left":
            current_hash = hash_internal_node(sibling_hash, current_hash)
        elif direction == "right":
            current_hash = hash_internal_node(current_hash, sibling_hash)
        else:
            raise ValueError(f"Dirección inválida en la prueba: {direction}")

    return current_hash == expected_root, current_hash