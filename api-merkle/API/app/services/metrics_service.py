from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from statistics import mean
from typing import Any, Dict, List

from API.app.crypto.merkle import (
    build_merkle_tree,
    generate_inclusion_proof,
    get_merkle_root,
    hash_leaf,
    verify_inclusion_proof,
)
from API.app.crypto.signatures import (
    base64_to_bytes,
    generate_signature_keypair,
    sign_root_hash,
    verify_root_hash_signature,
)
from API.app.models.metrics_models import MerkleMetricsDemoRequest


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bytes_len_json(payload: Any) -> int:
    return len(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )


def _avg(values: List[float]) -> float:
    if not values:
        return 0.0
    return round(mean(values), 3)


def _synthetic_public_key_b64(index: int) -> str:
    """
    Generate deterministic synthetic public-key material.

    This is not intended to be a real PQC public key. The metrics endpoint is
    measuring Merkle tree and proof behaviour, so synthetic stable values are
    enough and avoid depending on external key generation.
    """

    raw = f"synthetic-public-key-material-{index:06d}".encode("utf-8")
    return base64.b64encode(raw).decode("utf-8")


def _make_synthetic_entry(index: int) -> Dict[str, Any]:
    return {
        "identity": f"service-{index:04d}.internal",
        "public_key_b64": _synthetic_public_key_b64(index),
        "metadata": {
            "source": "metrics-demo",
            "environment": "synthetic",
            "index": index,
        },
        "valid_from": "2026-01-01T00:00:00+00:00",
        "valid_until": "2027-01-01T00:00:00+00:00",
    }


def _build_consistency_payload(
    old_leaf_hashes: List[str],
    new_leaf_hashes: List[str],
) -> Dict[str, Any]:
    """
    Build a simple append-only consistency payload.

    This does not try to reproduce a production Certificate Transparency
    consistency proof. It measures the cost of checking that the newer synthetic
    registry state extends the older state without modifying its prefix.
    """

    return {
        "old_tree_size": len(old_leaf_hashes),
        "new_tree_size": len(new_leaf_hashes),
        "old_root_hash": get_merkle_root(old_leaf_hashes),
        "new_root_hash": get_merkle_root(new_leaf_hashes),
        "old_leaf_hashes": old_leaf_hashes,
        "appended_leaf_hashes": new_leaf_hashes[len(old_leaf_hashes):],
    }


def _verify_consistency_payload(payload: Dict[str, Any]) -> bool:
    old_leaf_hashes = payload["old_leaf_hashes"]
    appended_leaf_hashes = payload["appended_leaf_hashes"]

    reconstructed_old_root = get_merkle_root(old_leaf_hashes)
    reconstructed_new_root = get_merkle_root(old_leaf_hashes + appended_leaf_hashes)

    return (
        reconstructed_old_root == payload["old_root_hash"]
        and reconstructed_new_root == payload["new_root_hash"]
    )


def run_merkle_metrics_demo(request: MerkleMetricsDemoRequest) -> Dict[str, Any]:
    """
    Run a synthetic in-memory Merkle registry metrics demo.

    The demo does not modify the persistent registry database. It generates
    synthetic entries, builds a Merkle tree, generates and verifies an inclusion
    proof, checks a simple append-only consistency payload and signs/verifies
    the Merkle root using ML-DSA.
    """

    entries_count = request.entries_count
    iterations = request.iterations

    proof_index = (
        request.proof_index
        if request.proof_index is not None
        else entries_count // 2
    )

    if proof_index >= entries_count:
        raise ValueError("proof_index must be lower than entries_count.")

    old_tree_size = max(1, entries_count // 2)

    synthetic_entries = [
        _make_synthetic_entry(index)
        for index in range(entries_count)
    ]

    signature_keygen_start = time.perf_counter()
    signature_keys = generate_signature_keypair(request.signature_algorithm)
    signature_keygen_end = time.perf_counter()

    timings: Dict[str, List[float]] = {
        "leaf_generation_ms": [],
        "tree_building_ms": [],
        "root_extraction_ms": [],
        "inclusion_proof_generation_ms": [],
        "inclusion_proof_verification_ms": [],
        "consistency_payload_generation_ms": [],
        "consistency_payload_verification_ms": [],
        "root_signature_generation_ms": [],
        "root_signature_verification_ms": [],
        "total_iteration_ms": [],
    }

    last_leaf_hashes: List[str] = []
    last_tree: List[List[str]] = []
    last_root_hash = ""
    last_proof: List[Dict[str, str]] = []
    last_consistency_payload: Dict[str, Any] = {}
    last_signature_b64 = ""

    inclusion_proof_valid = False
    consistency_proof_valid = False
    root_signature_valid = False

    for _ in range(iterations):
        iteration_start = time.perf_counter()

        leaf_start = time.perf_counter()
        leaf_hashes = [hash_leaf(entry) for entry in synthetic_entries]
        leaf_end = time.perf_counter()

        tree_start = time.perf_counter()
        tree = build_merkle_tree(leaf_hashes)
        tree_end = time.perf_counter()

        root_start = time.perf_counter()
        root_hash = tree[-1][0] if tree else ""
        root_end = time.perf_counter()

        proof_start = time.perf_counter()
        proof = generate_inclusion_proof(leaf_hashes, proof_index)
        proof_end = time.perf_counter()

        verify_proof_start = time.perf_counter()
        inclusion_proof_valid, computed_root = verify_inclusion_proof(
            leaf_hash=leaf_hashes[proof_index],
            proof=proof,
            expected_root=root_hash,
        )
        verify_proof_end = time.perf_counter()

        consistency_start = time.perf_counter()
        old_leaf_hashes = leaf_hashes[:old_tree_size]
        consistency_payload = _build_consistency_payload(
            old_leaf_hashes=old_leaf_hashes,
            new_leaf_hashes=leaf_hashes,
        )
        consistency_end = time.perf_counter()

        verify_consistency_start = time.perf_counter()
        consistency_proof_valid = _verify_consistency_payload(consistency_payload)
        verify_consistency_end = time.perf_counter()

        sign_start = time.perf_counter()
        signature_b64 = sign_root_hash(
            root_hash=root_hash,
            secret_key_b64=signature_keys["secret_key_b64"],
            algorithm=request.signature_algorithm,
        )
        sign_end = time.perf_counter()

        verify_signature_start = time.perf_counter()
        root_signature_valid = verify_root_hash_signature(
            root_hash=root_hash,
            signature_b64=signature_b64,
            public_key_b64=signature_keys["public_key_b64"],
            algorithm=request.signature_algorithm,
        )
        verify_signature_end = time.perf_counter()

        iteration_end = time.perf_counter()

        timings["leaf_generation_ms"].append((leaf_end - leaf_start) * 1000)
        timings["tree_building_ms"].append((tree_end - tree_start) * 1000)
        timings["root_extraction_ms"].append((root_end - root_start) * 1000)
        timings["inclusion_proof_generation_ms"].append((proof_end - proof_start) * 1000)
        timings["inclusion_proof_verification_ms"].append((verify_proof_end - verify_proof_start) * 1000)
        timings["consistency_payload_generation_ms"].append((consistency_end - consistency_start) * 1000)
        timings["consistency_payload_verification_ms"].append((verify_consistency_end - verify_consistency_start) * 1000)
        timings["root_signature_generation_ms"].append((sign_end - sign_start) * 1000)
        timings["root_signature_verification_ms"].append((verify_signature_end - verify_signature_start) * 1000)
        timings["total_iteration_ms"].append((iteration_end - iteration_start) * 1000)

        last_leaf_hashes = leaf_hashes
        last_tree = tree
        last_root_hash = root_hash
        last_proof = proof
        last_consistency_payload = consistency_payload
        last_signature_b64 = signature_b64

    proof_json_size = _bytes_len_json(last_proof)
    consistency_json_size = _bytes_len_json(last_consistency_payload)

    root_signature_raw = base64_to_bytes(last_signature_b64)
    public_key_raw = base64_to_bytes(signature_keys["public_key_b64"])
    secret_key_raw = base64_to_bytes(signature_keys["secret_key_b64"])

    measurements = {
        "signature_keypair_generation_ms": round(
            (signature_keygen_end - signature_keygen_start) * 1000,
            3,
        ),
        "leaf_generation_avg_ms": _avg(timings["leaf_generation_ms"]),
        "tree_building_avg_ms": _avg(timings["tree_building_ms"]),
        "root_extraction_avg_ms": _avg(timings["root_extraction_ms"]),
        "inclusion_proof_generation_avg_ms": _avg(timings["inclusion_proof_generation_ms"]),
        "inclusion_proof_verification_avg_ms": _avg(timings["inclusion_proof_verification_ms"]),
        "consistency_payload_generation_avg_ms": _avg(timings["consistency_payload_generation_ms"]),
        "consistency_payload_verification_avg_ms": _avg(timings["consistency_payload_verification_ms"]),
        "root_signature_generation_avg_ms": _avg(timings["root_signature_generation_ms"]),
        "root_signature_verification_avg_ms": _avg(timings["root_signature_verification_ms"]),
        "total_iteration_avg_ms": _avg(timings["total_iteration_ms"]),
    }

    sizes_bytes = {
        "leaf_hash_raw": 32,
        "leaf_hash_hex": len(last_leaf_hashes[0].encode("utf-8")) if last_leaf_hashes else 0,
        "root_hash_raw": 32,
        "root_hash_hex": len(last_root_hash.encode("utf-8")),
        "inclusion_proof_json": proof_json_size,
        "consistency_payload_json": consistency_json_size,
        "signature_public_key": len(public_key_raw),
        "signature_secret_key": len(secret_key_raw),
        "root_signature": len(root_signature_raw),
        "root_signature_b64": len(last_signature_b64.encode("utf-8")),
    }

    structure = {
        "leaf_count": entries_count,
        "tree_levels": len(last_tree),
        "root_hash": last_root_hash,
        "proof_index": proof_index,
        "inclusion_proof_steps": len(last_proof),
        "old_tree_size": old_tree_size,
        "new_tree_size": entries_count,
        "appended_leaf_count": entries_count - old_tree_size,
        "generated_at": _now_iso(),
    }

    return {
        "entries_count": entries_count,
        "iterations": iterations,
        "proof_index": proof_index,
        "hash_algorithm": "SHA-256",
        "signature_algorithm": request.signature_algorithm,
        "validation": {
            "inclusion_proof_valid": inclusion_proof_valid,
            "consistency_payload_valid": consistency_proof_valid,
            "root_signature_valid": root_signature_valid,
        },
        "structure": structure,
        "measurements": measurements,
        "sizes_bytes": sizes_bytes,
        "notes": [
            "This endpoint runs an in-memory synthetic metrics demo and does not modify registry.db.",
            "Timing values are averaged across the requested number of iterations.",
            "Consistency measurement checks append-only reconstruction for synthetic old/new registry states.",
            "Signature measurements use ML-DSA over the Merkle root hash.",
        ],
    }