from __future__ import annotations

import base64
import hashlib
import time
from typing import Any, Dict

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _fingerprint(data: bytes, length: int = 24) -> str:
    return hashlib.sha256(data).hexdigest()[:length]


def _new_kem(kem_algorithm: str):
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


def encapsulate_session_secret(
    server_public_key: bytes,
    kem_algorithm: str,
) -> tuple[str, bytes, bytes, Dict[str, float]]:
    """
    Client-side step: encapsulate a shared secret using the server ML-KEM public key.
    """

    start = time.perf_counter()

    kem, selected_algorithm = _new_kem(kem_algorithm)
    ciphertext, shared_secret = kem.encap_secret(server_public_key)

    end = time.perf_counter()

    measurements = {
        "client_kem_encapsulation_ms": round((end - start) * 1000, 3),
    }

    return selected_algorithm, ciphertext, shared_secret, measurements


def encrypt_client_request(
    session_key: bytes,
    plaintext_payload: str,
    aad: bytes,
) -> tuple[bytes, bytes, bytes, Dict[str, float]]:
    """
    Client-side step: encrypt request payload with AES-GCM.
    """

    import secrets

    start = time.perf_counter()

    aesgcm = AESGCM(session_key)
    nonce = secrets.token_bytes(12)

    ciphertext_with_tag = aesgcm.encrypt(
        nonce=nonce,
        data=plaintext_payload.encode("utf-8"),
        associated_data=aad,
    )

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    end = time.perf_counter()

    measurements = {
        "client_request_encryption_ms": round((end - start) * 1000, 3),
    }

    return nonce, ciphertext, tag, measurements


def decrypt_server_response(
    session_key: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    aad: bytes,
) -> tuple[str, Dict[str, float]]:
    """
    Client-side step: decrypt server response with AES-GCM.
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
        "client_response_decryption_ms": round((end - start) * 1000, 3),
    }

    return plaintext.decode("utf-8"), measurements


def describe_kem_ciphertext(ciphertext: bytes) -> Dict[str, Any]:
    return {
        "ciphertext_b64": _b64(ciphertext),
        "ciphertext_size_bytes": len(ciphertext),
        "ciphertext_fingerprint": _fingerprint(ciphertext),
    }