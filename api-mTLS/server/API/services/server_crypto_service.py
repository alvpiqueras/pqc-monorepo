from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HKDF_INFO = b"api-mtls-application-level-session-key"


def b64decode_bytes(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value)

    except Exception as exc:
        raise ValueError(f"Invalid base64 value for '{field_name}'.") from exc


def b64encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def derive_aes_gcm_key(
    shared_secret: bytes,
) -> tuple[bytes, Dict[str, float]]:
    """
    Derive an AES-256-GCM key from the ML-KEM shared secret.
    """

    start = time.perf_counter()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    )

    key = hkdf.derive(shared_secret)

    end = time.perf_counter()

    return key, {
        "server_hkdf_key_derivation_ms": round((end - start) * 1000, 3),
    }


def decapsulate_shared_secret(
    kem_object: Any,
    kem_ciphertext_b64: str,
) -> tuple[bytes, Dict[str, float]]:
    """
    Decapsulate the ML-KEM ciphertext received from the client.
    """

    total_start = time.perf_counter()

    kem_ciphertext = b64decode_bytes(
        kem_ciphertext_b64,
        "kem_ciphertext_b64",
    )

    decapsulation_start = time.perf_counter()

    try:
        shared_secret = kem_object.decap_secret(kem_ciphertext)

    except Exception as exc:
        raise RuntimeError(f"ML-KEM decapsulation failed: {exc}") from exc

    decapsulation_end = time.perf_counter()

    return shared_secret, {
        "server_kem_ciphertext_size_bytes": len(kem_ciphertext),
        "server_shared_secret_size_bytes": len(shared_secret),
        "server_ml_kem_decapsulation_ms": round(
            (decapsulation_end - decapsulation_start) * 1000,
            3,
        ),
        "server_ml_kem_decapsulation_total_ms": round(
            (time.perf_counter() - total_start) * 1000,
            3,
        ),
    }


def decrypt_payload_with_aes_gcm(
    aes_key: bytes,
    nonce_b64: str,
    aad_b64: str,
    encrypted_payload_b64: str,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    """
    Decrypt the AES-GCM protected request payload.
    """

    total_start = time.perf_counter()

    nonce = b64decode_bytes(nonce_b64, "nonce_b64")
    aad = b64decode_bytes(aad_b64, "aad_b64")
    encrypted_payload = b64decode_bytes(
        encrypted_payload_b64,
        "encrypted_payload_b64",
    )

    decrypt_start = time.perf_counter()

    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(
            nonce,
            encrypted_payload,
            aad,
        )

    except Exception as exc:
        raise RuntimeError(f"AES-GCM payload decryption failed: {exc}") from exc

    decrypt_end = time.perf_counter()

    try:
        payload = json.loads(plaintext.decode("utf-8"))

    except Exception as exc:
        raise ValueError("Decrypted payload is not valid JSON.") from exc

    return payload, {
        "server_aes_gcm_nonce_size_bytes": len(nonce),
        "server_aes_gcm_aad_size_bytes": len(aad),
        "server_encrypted_payload_size_bytes": len(encrypted_payload),
        "server_decrypted_payload_size_bytes": len(plaintext),
        "server_aes_gcm_decryption_ms": round(
            (decrypt_end - decrypt_start) * 1000,
            3,
        ),
        "server_aes_gcm_decryption_total_ms": round(
            (time.perf_counter() - total_start) * 1000,
            3,
        ),
    }


def encrypt_payload_with_aes_gcm(
    aes_key: bytes,
    payload: Dict[str, Any],
    aad_metadata: Dict[str, Any],
) -> tuple[Dict[str, str], Dict[str, float]]:
    """
    Encrypt the server application response with AES-256-GCM.

    A fresh nonce is generated for the response. The same AES key derived from
    the ML-KEM shared secret is reused for this session, but the nonce and AAD
    are different from the request.
    """

    total_start = time.perf_counter()

    nonce = os.urandom(12)

    plaintext = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    aad = json.dumps(
        aad_metadata,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    encrypt_start = time.perf_counter()

    try:
        aesgcm = AESGCM(aes_key)
        encrypted_payload = aesgcm.encrypt(
            nonce,
            plaintext,
            aad,
        )

    except Exception as exc:
        raise RuntimeError(f"AES-GCM response encryption failed: {exc}") from exc

    encrypt_end = time.perf_counter()

    encrypted_response = {
        "response_nonce_b64": b64encode_bytes(nonce),
        "response_aad_b64": b64encode_bytes(aad),
        "encrypted_response_b64": b64encode_bytes(encrypted_payload),
    }

    measurements = {
        "server_response_aes_gcm_nonce_size_bytes": len(nonce),
        "server_response_aes_gcm_aad_size_bytes": len(aad),
        "server_response_plaintext_size_bytes": len(plaintext),
        "server_encrypted_response_size_bytes": len(encrypted_payload),
        "server_aes_gcm_response_encryption_ms": round(
            (encrypt_end - encrypt_start) * 1000,
            3,
        ),
        "server_aes_gcm_response_encryption_total_ms": round(
            (time.perf_counter() - total_start) * 1000,
            3,
        ),
    }

    return encrypted_response, measurements