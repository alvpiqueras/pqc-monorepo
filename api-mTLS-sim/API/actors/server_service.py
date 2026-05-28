from __future__ import annotations

import base64
import hashlib
import time
import secrets
from typing import Any, Dict, Tuple

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _fingerprint(data: bytes, length: int = 24) -> str:
    return hashlib.sha256(data).hexdigest()[:length]


def _new_kem(kem_algorithm: str):
    """
    Create a liboqs KEM object.

    Different liboqs builds may expose either ML-KEM-* or Kyber* names.
    This helper tries the requested name first and then common fallbacks.
    """

    candidates = [
        kem_algorithm,
        "ML-KEM-768",
        "Kyber768",
        "Kyber768-90s",
    ]

    last_error: Exception | None = None

    for candidate in candidates:
        try:
            return oqs.KeyEncapsulation(candidate), candidate
        except Exception as exc:
            last_error = exc

    raise RuntimeError(
        f"Could not initialize any supported KEM. Last error: {last_error}"
    )


def generate_ephemeral_kem_keypair(
    kem_algorithm: str,
) -> Tuple[Any, str, bytes, Dict[str, float]]:
    """
    Server-side step: generate an ephemeral ML-KEM keypair.

    In the simulation, the server exposes the public key to the client service.
    The private key remains inside the KEM object until decapsulation.
    """

    start = time.perf_counter()

    kem, selected_algorithm = _new_kem(kem_algorithm)
    public_key = kem.generate_keypair()

    end = time.perf_counter()

    measurements = {
        "server_kem_keypair_generation_ms": round((end - start) * 1000, 3),
    }

    return kem, selected_algorithm, public_key, measurements


def decapsulate_session_secret(
    kem: Any,
    ciphertext: bytes,
) -> tuple[bytes, Dict[str, float]]:
    """
    Server-side step: decapsulate the ML-KEM ciphertext to recover the shared secret.
    """

    start = time.perf_counter()

    shared_secret = kem.decap_secret(ciphertext)

    end = time.perf_counter()

    measurements = {
        "server_kem_decapsulation_ms": round((end - start) * 1000, 3),
    }

    return shared_secret, measurements


def decrypt_client_request(
    session_key: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    aad: bytes,
) -> tuple[str, Dict[str, float]]:
    """
    Server-side step: decrypt the client request using AES-GCM.
    """

    start = time.perf_counter()

    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(
        nonce=nonce,
        data=ciphertext_with_tag,
        associated_data=aad,
    )

    end = time.perf_counter()

    measurements = {
        "server_request_decryption_ms": round((end - start) * 1000, 3),
    }

    return plaintext.decode("utf-8"), measurements


def build_server_response(
    client_service_id: str,
    server_service_id: str,
    action: str,
    resource: str,
    decrypted_request_payload: str,
) -> Dict[str, Any]:
    """
    Simulated server-side business processing.

    This is intentionally simple: the objective of api-mtls-sim is mutual
    authentication and protected exchange, not authorization policies.
    """

    return {
        "processed_by": server_service_id,
        "request_from": client_service_id,
        "action": action,
        "resource": resource,
        "status": "success",
        "classification": "internal-service-response",
        "received_payload": decrypted_request_payload,
        "message": (
            "Request processed after successful mutual authentication and "
            "protected channel establishment."
        ),
    }


def encrypt_server_response(
    session_key: bytes,
    response_payload: bytes,
    aad: bytes,
) -> tuple[bytes, bytes, bytes, Dict[str, float]]:
    """
    Server-side step: encrypt the response with AES-GCM.
    """

    start = time.perf_counter()

    aesgcm = AESGCM(session_key)
    nonce = secrets.token_bytes(12)

    ciphertext_with_tag = aesgcm.encrypt(
        nonce=nonce,
        data=response_payload,
        associated_data=aad,
    )

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    end = time.perf_counter()

    measurements = {
        "server_response_encryption_ms": round((end - start) * 1000, 3),
    }

    return nonce, ciphertext, tag, measurements


def describe_server_kem_public_key(public_key: bytes) -> Dict[str, Any]:
    return {
        "public_key_b64": _b64(public_key),
        "public_key_size_bytes": len(public_key),
        "public_key_fingerprint": _fingerprint(public_key),
    }