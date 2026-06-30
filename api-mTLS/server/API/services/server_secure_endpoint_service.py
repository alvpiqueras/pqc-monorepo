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
    encrypt_payload_with_aes_gcm,
)
from services.server_identity_service import require_configured_server_identity
from services.server_session_service import (
    get_handshake_session,
    mark_handshake_session_used,
)


def _build_application_response(
    decrypted_payload: Dict[str, Any],
    request_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build a deterministic demo application response.

    This simulates the server business logic after decrypting the request.
    """

    customer_id = decrypted_payload.get("customer_id", "unknown-customer")
    operation = request_metadata.get("operation", "unknown-operation")

    return {
        "operation": operation,
        "customer_id": customer_id,
        "processed_by": settings.SERVICE_ID,
        "decision": "request accepted",
        "risk_level": "low",
        "message": (
            "The encrypted request was verified, decrypted and processed "
            "successfully by the server service."
        ),
    }


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
    - decrypts the request payload;
    - builds an application response;
    - encrypts the response with AES-GCM.
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
        steps.append(
            "Server rejected the request because client certificate verification failed."
        )

        total_end = time.perf_counter()

        measurements["server_secure_endpoint_total_ms"] = round(
            (total_end - total_start) * 1000,
            3,
        )

        return {
            "secure_request_processed": False,
            "request_decrypted_by_server": False,
            "server_verified_client_certificate": False,
            "response_encrypted_by_server": False,
            "reason": (
                "The server rejected the encrypted request because the client "
                "certificate could not be verified."
            ),
            "decrypted_payload": None,
            "encrypted_response_b64": None,
            "response_nonce_b64": None,
            "response_aad_b64": None,
            "response_metadata": {},
            "client_certificate_verification": verification,
            "kem": {
                "algorithm": request.kem_algorithm,
                "shared_secret_established": False,
            },
            "encryption": {
                "algorithm": request.encryption_algorithm,
                "request_decrypted": False,
                "response_encrypted": False,
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

    steps.append("Server decrypted the request successfully.")
    steps.append("Server processes the decrypted application payload.")

    application_response = _build_application_response(
        decrypted_payload=decrypted_payload,
        request_metadata=request.metadata,
    )

    response_metadata = {
        "session_id": request.session_id,
        "operation": request.metadata.get("operation"),
        "server_service_id": identity.get("service_id", settings.SERVICE_ID),
        "client_service_id": request.metadata.get("client_service_id"),
        "kem_algorithm": request.kem_algorithm,
        "encryption_algorithm": request.encryption_algorithm,
        "response_type": "encrypted-application-response",
    }

    steps.append("Server encrypts the application response with AES-GCM.")

    encrypted_response, response_encryption_metrics = encrypt_payload_with_aes_gcm(
        aes_key=aes_key,
        payload=application_response,
        aad_metadata=response_metadata,
    )
    measurements.update(response_encryption_metrics)

    mark_handshake_session_used(request.session_id)

    steps.append("Server encrypted the response successfully.")
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
        "response_encrypted_by_server": True,
        "reason": (
            "The server verified the client certificate, established the same "
            "ML-KEM shared secret, decrypted the AES-GCM protected request and "
            "encrypted the application response."
        ),
        "decrypted_payload": decrypted_payload,
        "encrypted_response_b64": encrypted_response["encrypted_response_b64"],
        "response_nonce_b64": encrypted_response["response_nonce_b64"],
        "response_aad_b64": encrypted_response["response_aad_b64"],
        "response_metadata": response_metadata,
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
            "response_encrypted": True,
            "request_aad_received": True,
            "request_nonce_received": True,
            "response_aad_created": True,
            "response_nonce_created": True,
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