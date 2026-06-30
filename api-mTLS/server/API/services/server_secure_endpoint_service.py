from __future__ import annotations

import time
from typing import Any, Dict

from core.config import settings
from models.secure_endpoint_models import EncryptedRequestFromClient
from services.certificate_verification_service import verify_certificate_against_ca
from services.server_crypto_service import (
    decapsulate_shared_secret,
    decrypt_payload_with_aes_gcm,
    derive_aes_gcm_key,
)
from services.server_identity_service import require_configured_server_identity
from services.server_session_service import (
    get_handshake_session,
    mark_handshake_session_used,
)


def process_encrypted_request(
    request: EncryptedRequestFromClient,
) -> Dict[str, Any]:
    """
    Process an encrypted request sent by the client service.

    The server:
    - verifies the client certificate;
    - retrieves the handshake session;
    - decapsulates the ML-KEM shared secret;
    - derives the AES-GCM key;
    - decrypts the request payload.
    """

    total_start = time.perf_counter()

    steps: list[str] = [
        "Server received an encrypted request from the client.",
        "Server checks that its identity was configured during bootstrap.",
    ]

    measurements: Dict[str, float] = {}

    identity = require_configured_server_identity()

    steps.append("Server identity is configured.")
    steps.append("Server verifies the client certificate against the configured CA.")

    verification = verify_certificate_against_ca(
        peer_certificate_pem=request.client_certificate_pem,
        ca_certificate_pem=identity["ca_certificate_pem"],
        expected_subject_fragment=identity["expected_client_subject"],
    )

    for key, value in verification.get("measurements", {}).items():
        measurements[f"server_client_certificate_{key}"] = value

    if not verification["verified"]:
        steps.append("Server rejected the request because client certificate verification failed.")

        total_end = time.perf_counter()

        measurements["server_secure_endpoint_total_ms"] = round(
            (total_end - total_start) * 1000,
            3,
        )

        return {
            "secure_request_processed": False,
            "request_decrypted_by_server": False,
            "server_verified_client_certificate": False,
            "reason": (
                "The server rejected the encrypted request because the client "
                "certificate could not be verified."
            ),
            "decrypted_payload": None,
            "client_certificate_verification": verification,
            "kem": {
                "algorithm": request.kem_algorithm,
                "shared_secret_established": False,
            },
            "encryption": {
                "algorithm": request.encryption_algorithm,
                "request_decrypted": False,
            },
            "server_service": {
                "service_name": settings.SERVICE_NAME,
                "service_id": identity.get("service_id", settings.SERVICE_ID),
                "service_role": identity.get("service_role", settings.SERVICE_ROLE),
            },
            "steps": steps,
            "measurements": measurements,
        }

    steps.append("Server verified the client certificate successfully.")
    steps.append("Server retrieves the temporary ML-KEM handshake session.")

    session = get_handshake_session(request.session_id)

    if session.get("used"):
        raise RuntimeError(
            "Handshake session has already been used. Start a new handshake first."
        )

    if session.get("kem_algorithm") != request.kem_algorithm:
        raise ValueError(
            "KEM algorithm mismatch between request and stored handshake session."
        )

    steps.append("Server decapsulates the ML-KEM ciphertext sent by the client.")

    shared_secret, kem_metrics = decapsulate_shared_secret(
        kem_object=session["kem_object"],
        kem_ciphertext_b64=request.kem_ciphertext_b64,
    )
    measurements.update(kem_metrics)

    steps.append("Server derives an AES-256-GCM key using HKDF.")

    aes_key, hkdf_metrics = derive_aes_gcm_key(shared_secret)
    measurements.update(hkdf_metrics)

    steps.append("Server decrypts the AES-GCM protected request payload.")

    decrypted_payload, decrypt_metrics = decrypt_payload_with_aes_gcm(
        aes_key=aes_key,
        nonce_b64=request.nonce_b64,
        aad_b64=request.aad_b64,
        encrypted_payload_b64=request.encrypted_payload_b64,
    )
    measurements.update(decrypt_metrics)

    mark_handshake_session_used(request.session_id)

    steps.append("Server decrypted the request successfully.")
    steps.append("Server marks the handshake session as used.")

    total_end = time.perf_counter()

    measurements["server_secure_endpoint_total_ms"] = round(
        (total_end - total_start) * 1000,
        3,
    )

    return {
        "secure_request_processed": True,
        "request_decrypted_by_server": True,
        "server_verified_client_certificate": True,
        "reason": (
            "The server verified the client certificate, established the same "
            "ML-KEM shared secret and decrypted the AES-GCM protected request."
        ),
        "decrypted_payload": decrypted_payload,
        "client_certificate_verification": verification,
        "kem": {
            "algorithm": request.kem_algorithm,
            "shared_secret_established": True,
            "ciphertext_received": True,
            "session_id": request.session_id,
        },
        "encryption": {
            "algorithm": request.encryption_algorithm,
            "request_decrypted": True,
            "aad_received": True,
            "nonce_received": True,
        },
        "server_service": {
            "service_name": settings.SERVICE_NAME,
            "service_id": identity.get("service_id", settings.SERVICE_ID),
            "service_role": identity.get("service_role", settings.SERVICE_ROLE),
            "processed_operation": request.metadata.get("operation"),
        },
        "steps": steps,
        "measurements": measurements,
    }