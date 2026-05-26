from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models.identity_models import (
    SecureHttpsConnectionDemoRequest,
    VerifyIntranetIdentityRequest,
)
from services.identity_verification_service import verify_intranet_identity


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _generate_session_id() -> str:
    return f"https_sess_{secrets.token_hex(8)}"


def _key_fingerprint(key: bytes) -> str:
    """
    Return a short non-sensitive fingerprint of the generated session key.

    The raw session key is never returned by the API.
    """

    return hashlib.sha256(key).hexdigest()[:24]


def simulate_secure_https_connection(
    request: SecureHttpsConnectionDemoRequest,
) -> Dict[str, Any]:
    """
    Simulate a protected internal HTTPS connection.

    Important scope limitation:
    - This is not a real TLS implementation.
    - This demo does not use ML-KEM or any PQC KEM for key exchange.
    - PQC appears in the server certificate validation step.
    - AES-GCM is used only to model the encrypted application-data phase after
      the client has accepted the server identity.
    """

    total_start = time.perf_counter()

    verification_start = time.perf_counter()

    identity_verification = verify_intranet_identity(
        VerifyIntranetIdentityRequest(
            client_id=request.client_id,
            ca_artifact_id=request.ca_artifact_id,
            server_certificate_id=request.server_certificate_id,
            expected_subject=request.expected_subject,
        )
    )

    verification_end = time.perf_counter()

    if not identity_verification["trusted"]:
        total_end = time.perf_counter()

        return {
            "connection_established": False,
            "reason": (
                "Secure HTTPS session was not established because the server "
                "identity could not be trusted."
            ),
            "client": identity_verification["client"],
            "server": identity_verification["server"],
            "session": {
                "session_id": None,
                "mode": "server-authenticated-https-demo",
                "server_authenticated": False,
                "client_authenticated": False,
                "pqc_key_exchange_used": False,
                "key_exchange_note": (
                    "No ML-KEM/PQC key exchange is performed in api-intranet. "
                    "This is reserved for more advanced APIs such as api-mTLS."
                ),
                "symmetric_cipher": None,
            },
            "identity_verification": identity_verification,
            "encrypted_request": None,
            "decrypted_at_server": None,
            "steps": [
                f"Client '{request.client_id}' requests '{request.requested_resource}'.",
                "The intranet portal presents its PQC X.509 server certificate.",
                "The client verifies the certificate against the registered internal CA.",
                "The server identity verification failed.",
                "No HTTPS session key is generated and no application payload is encrypted.",
            ],
            "measurements": {
                **identity_verification["measurements"],
                "identity_verification_phase_ms": round(
                    (verification_end - verification_start) * 1000,
                    3,
                ),
                "session_key_generation_ms": 0.0,
                "aes_gcm_encryption_ms": 0.0,
                "aes_gcm_decryption_ms": 0.0,
                "total_secure_https_demo_ms": round(
                    (total_end - total_start) * 1000,
                    3,
                ),
            },
        }

    keygen_start = time.perf_counter()

    session_id = _generate_session_id()
    session_key = AESGCM.generate_key(bit_length=256)
    key_fingerprint = _key_fingerprint(session_key)

    keygen_end = time.perf_counter()

    encryption_start = time.perf_counter()

    aesgcm = AESGCM(session_key)
    nonce = secrets.token_bytes(12)

    plaintext = request.payload.encode("utf-8")
    aad = (
        f"{request.client_id}|{request.requested_resource}|{request.expected_subject}"
    ).encode("utf-8")

    ciphertext_with_tag = aesgcm.encrypt(
        nonce=nonce,
        data=plaintext,
        associated_data=aad,
    )

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    encryption_end = time.perf_counter()

    decryption_start = time.perf_counter()

    decrypted = aesgcm.decrypt(
        nonce=nonce,
        data=ciphertext_with_tag,
        associated_data=aad,
    )

    decryption_end = time.perf_counter()
    total_end = time.perf_counter()

    steps = [
        f"Client '{request.client_id}' requests internal resource '{request.requested_resource}'.",
        "The intranet portal presents its PQC X.509 server certificate.",
        "The client verifies the server certificate against the internal CA artifact.",
        "The client checks that the certificate subject matches the expected intranet identity.",
        "Server identity verification succeeds.",
        (
            "A simulated HTTPS session key is generated locally for the demo. "
            "No ML-KEM or PQC key exchange is performed in this API."
        ),
        "The HTTP payload is encrypted with AES-256-GCM.",
        "The intranet server decrypts the payload inside the simulated protected channel.",
    ]

    return {
        "connection_established": True,
        "reason": (
            "Secure internal HTTPS demo session established after successful "
            "server identity verification."
        ),
        "client": identity_verification["client"],
        "server": identity_verification["server"],
        "session": {
            "session_id": session_id,
            "mode": "server-authenticated-https-demo",
            "server_authenticated": True,
            "client_authenticated": False,
            "pqc_certificate_used": True,
            "pqc_key_exchange_used": False,
            "key_exchange_note": (
                "api-intranet validates a PQC X.509 server certificate, but does "
                "not perform ML-KEM/PQC key exchange. The AES-GCM key is generated "
                "locally to simulate the protected application-data phase of HTTPS."
            ),
            "symmetric_cipher": "AES-256-GCM",
            "session_key_fingerprint": key_fingerprint,
        },
        "identity_verification": identity_verification,
        "encrypted_request": {
            "http_method": request.http_method,
            "requested_resource": request.requested_resource,
            "ciphertext_b64": _b64(ciphertext),
            "nonce_b64": _b64(nonce),
            "tag_b64": _b64(tag),
            "aad_b64": _b64(aad),
            "plaintext_size_bytes": len(plaintext),
            "ciphertext_size_bytes": len(ciphertext),
            "tag_size_bytes": len(tag),
            "nonce_size_bytes": len(nonce),
        },
        "decrypted_at_server": {
            "success": True,
            "payload": decrypted.decode("utf-8"),
            "resource": request.requested_resource,
            "classification": "internal-only",
        },
        "steps": steps,
        "measurements": {
            **identity_verification["measurements"],
            "identity_verification_phase_ms": round(
                (verification_end - verification_start) * 1000,
                3,
            ),
            "session_key_generation_ms": round(
                (keygen_end - keygen_start) * 1000,
                3,
            ),
            "aes_gcm_encryption_ms": round(
                (encryption_end - encryption_start) * 1000,
                3,
            ),
            "aes_gcm_decryption_ms": round(
                (decryption_end - decryption_start) * 1000,
                3,
            ),
            "total_secure_https_demo_ms": round(
                (total_end - total_start) * 1000,
                3,
            ),
        },
    }