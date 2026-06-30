from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict

import oqs
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


def encapsulate_shared_secret(
    kem_algorithm: str,
    kem_public_key_b64: str,
) -> tuple[bytes, str, Dict[str, float]]:
    """
    Encapsulate a shared secret using the server ephemeral ML-KEM public key.

    The client obtains:
    - shared_secret: kept locally and used to derive AES-GCM key;
    - kem_ciphertext_b64: sent to the server so it can decapsulate the same secret.
    """

    total_start = time.perf_counter()

    kem_public_key = b64decode_bytes(
        kem_public_key_b64,
        "kem_public_key_b64",
    )

    encapsulation_start = time.perf_counter()

    try:
        kem = oqs.KeyEncapsulation(kem_algorithm)
        kem_ciphertext, shared_secret = kem.encap_secret(kem_public_key)

    except Exception as exc:
        raise RuntimeError(
            f"ML-KEM encapsulation failed with algorithm '{kem_algorithm}': {exc}"
        ) from exc

    encapsulation_end = time.perf_counter()

    kem_ciphertext_b64 = b64encode_bytes(kem_ciphertext)

    return shared_secret, kem_ciphertext_b64, {
        "client_kem_public_key_size_bytes": len(kem_public_key),
        "client_kem_ciphertext_size_bytes": len(kem_ciphertext),
        "client_shared_secret_size_bytes": len(shared_secret),
        "client_ml_kem_encapsulation_ms": round(
            (encapsulation_end - encapsulation_start) * 1000,
            3,
        ),
        "client_ml_kem_encapsulation_total_ms": round(
            (time.perf_counter() - total_start) * 1000,
            3,
        ),
    }


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
        "client_hkdf_key_derivation_ms": round((end - start) * 1000, 3),
    }


def encrypt_payload_with_aes_gcm(
    aes_key: bytes,
    payload: Dict[str, Any],
    aad_metadata: Dict[str, Any],
) -> tuple[Dict[str, str], Dict[str, float]]:
    """
    Encrypt an application payload with AES-256-GCM.

    AES-GCM provides confidentiality and integrity. The AAD is authenticated but
    not encrypted, so it is useful for binding metadata such as session_id and operation.
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

    aesgcm = AESGCM(aes_key)
    encrypted_payload = aesgcm.encrypt(
        nonce,
        plaintext,
        aad,
    )

    encrypt_end = time.perf_counter()

    encrypted_request = {
        "nonce_b64": b64encode_bytes(nonce),
        "aad_b64": b64encode_bytes(aad),
        "encrypted_payload_b64": b64encode_bytes(encrypted_payload),
    }

    measurements = {
        "client_aes_gcm_nonce_size_bytes": len(nonce),
        "client_aes_gcm_aad_size_bytes": len(aad),
        "client_plaintext_payload_size_bytes": len(plaintext),
        "client_encrypted_payload_size_bytes": len(encrypted_payload),
        "client_aes_gcm_encryption_ms": round(
            (encrypt_end - encrypt_start) * 1000,
            3,
        ),
        "client_aes_gcm_encryption_total_ms": round(
            (time.perf_counter() - total_start) * 1000,
            3,
        ),
    }

    return encrypted_request, measurements


def decrypt_payload_with_aes_gcm(
    aes_key: bytes,
    nonce_b64: str,
    aad_b64: str,
    encrypted_payload_b64: str,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    """
    Decrypt the AES-GCM protected response returned by the server.
    """

    total_start = time.perf_counter()

    nonce = b64decode_bytes(nonce_b64, "response_nonce_b64")
    aad = b64decode_bytes(aad_b64, "response_aad_b64")
    encrypted_payload = b64decode_bytes(
        encrypted_payload_b64,
        "encrypted_response_b64",
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
        raise RuntimeError(f"AES-GCM response decryption failed: {exc}") from exc

    decrypt_end = time.perf_counter()

    try:
        payload = json.loads(plaintext.decode("utf-8"))

    except Exception as exc:
        raise ValueError("Decrypted server response is not valid JSON.") from exc

    return payload, {
        "client_response_aes_gcm_nonce_size_bytes": len(nonce),
        "client_response_aes_gcm_aad_size_bytes": len(aad),
        "client_encrypted_response_size_bytes": len(encrypted_payload),
        "client_decrypted_response_size_bytes": len(plaintext),
        "client_aes_gcm_response_decryption_ms": round(
            (decrypt_end - decrypt_start) * 1000,
            3,
        ),
        "client_aes_gcm_response_decryption_total_ms": round(
            (time.perf_counter() - total_start) * 1000,
            3,
        ),
    }