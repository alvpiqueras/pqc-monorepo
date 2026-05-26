import base64
import hashlib
import json
import os
import time
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEM_ALGORITHM = "ML-KEM-768"


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the ML-KEM shared secret.

    This is a simplified academic derivation using SHA-256.
    A production design should use a proper KDF with context binding.
    """

    return hashlib.sha256(shared_secret).digest()


def _measure_ms(start_time: float) -> float:
    return round((time.perf_counter() - start_time) * 1000, 4)


def establish_kem_session_and_encrypt_payload(
    plaintext_payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Simulate a secure payload exchange between two internal services.

    Actor model:
    - target API generates an ML-KEM keypair;
    - calling service encapsulates a shared secret;
    - calling service encrypts the payload with AES-GCM;
    - target API decapsulates the same shared secret;
    - target API decrypts the payload.
    """
    import oqs

    total_start = time.perf_counter()

    keygen_start = time.perf_counter()
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem_receiver:  # type: ignore[attr-defined]
        receiver_public_key = kem_receiver.generate_keypair()
        receiver_private_key = kem_receiver.export_secret_key()
    keygen_ms = _measure_ms(keygen_start)

    encapsulation_start = time.perf_counter()
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem_sender:  # type: ignore[attr-defined]
        ciphertext, sender_shared_secret = kem_sender.encap_secret(receiver_public_key)
    encapsulation_ms = _measure_ms(encapsulation_start)

    encryption_start = time.perf_counter()
    aes_key_sender = _derive_aes_key(sender_shared_secret)
    aesgcm_sender = AESGCM(aes_key_sender)
    nonce = os.urandom(12)

    plaintext_bytes = json.dumps(
        plaintext_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    encrypted_payload = aesgcm_sender.encrypt(
        nonce,
        plaintext_bytes,
        associated_data=None,
    )
    encryption_ms = _measure_ms(encryption_start)

    decapsulation_start = time.perf_counter()
    with oqs.KeyEncapsulation(
        KEM_ALGORITHM,
        secret_key=receiver_private_key,
    ) as kem_receiver_dec:  # type: ignore[attr-defined]
        receiver_shared_secret = kem_receiver_dec.decap_secret(ciphertext)
    decapsulation_ms = _measure_ms(decapsulation_start)

    decryption_start = time.perf_counter()
    aes_key_receiver = _derive_aes_key(receiver_shared_secret)
    aesgcm_receiver = AESGCM(aes_key_receiver)

    decrypted_payload_bytes = aesgcm_receiver.decrypt(
        nonce,
        encrypted_payload,
        associated_data=None,
    )

    decrypted_payload = json.loads(decrypted_payload_bytes.decode("utf-8"))
    decryption_ms = _measure_ms(decryption_start)

    secrets_match = sender_shared_secret == receiver_shared_secret
    payload_matches = decrypted_payload == plaintext_payload

    return {
        "kem_session_established": bool(secrets_match),
        "payload_encrypted": True,
        "payload_decrypted": bool(payload_matches),
        "kem_session_layer": {
            "kem_algorithm": KEM_ALGORITHM,
            "receiver_public_key_size_bytes": len(receiver_public_key),
            "ciphertext_size_bytes": len(ciphertext),
            "shared_secret_size_bytes": len(sender_shared_secret),
            "secrets_match": bool(secrets_match),
            "timings_ms": {
                "kem_keygen": keygen_ms,
                "encapsulation": encapsulation_ms,
                "decapsulation": decapsulation_ms,
            },
        },
        "payload_protection_layer": {
            "symmetric_cipher": "AES-256-GCM",
            "key_derivation": "SHA-256(shared_secret)",
            "plaintext_size_bytes": len(plaintext_bytes),
            "ciphertext_size_bytes": len(encrypted_payload),
            "nonce_b64": _b64encode(nonce),
            "encrypted_payload_b64": _b64encode(encrypted_payload),
            "decrypted_payload": decrypted_payload,
            "payload_matches": bool(payload_matches),
            "timings_ms": {
                "encryption": encryption_ms,
                "decryption": decryption_ms,
            },
        },
        "total_secure_channel_time_ms": _measure_ms(total_start),
    }