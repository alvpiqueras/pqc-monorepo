from __future__ import annotations

import time
from typing import Any, Dict

import httpx

from core.config import settings
from models.secure_call_models import (
    ClientEncryptedRequestRequest,
    ServerHandshakeResponse,
    ServerSecureEndpointResponse,
)
from services.certificate_verification_service import verify_certificate_against_ca
from services.client_crypto_service import (
    derive_aes_gcm_key,
    encapsulate_shared_secret,
    encrypt_payload_with_aes_gcm,
)
from services.client_identity_service import require_configured_client_identity


def _internal_headers() -> dict[str, str]:
    return {
        "X-MTLS-Demo-Token": settings.INTERNAL_DEMO_TOKEN,
    }


async def run_client_encrypted_request(
    request: ClientEncryptedRequestRequest,
) -> Dict[str, Any]:
    """
    Run the encrypted request flow from the client perspective.

    The client:
    - starts a handshake with the server;
    - verifies the server certificate;
    - encapsulates a shared secret with ML-KEM;
    - derives an AES-GCM key with HKDF;
    - encrypts the payload;
    - sends it to the server secure endpoint.
    """

    total_start = time.perf_counter()

    steps: list[str] = [
        "Client received an encrypted request demo from the gateway.",
        "Client checks that its identity was configured during bootstrap.",
    ]

    measurements: Dict[str, float] = {}

    identity = require_configured_client_identity()

    ca_certificate_pem = identity["ca_certificate_pem"]
    own_certificate_pem = identity["own_certificate_pem"]
    expected_server_subject = identity["expected_server_subject"]
    server_service_url = identity.get("server_service_url") or settings.SERVER_SERVICE_URL

    steps.append("Client identity is configured.")
    steps.append("Client starts a handshake with the server.")

    handshake_payload = {
        "operation": request.operation,
        "payload": request.payload,
        "client_service_id": identity.get("service_id", settings.SERVICE_ID),
        "phase": "encrypted-request",
    }

    handshake_start = time.perf_counter()

    async with httpx.AsyncClient(timeout=60.0) as client:
        handshake_response = await client.post(
            f"{server_service_url.rstrip('/')}/server/handshake/start",
            json=handshake_payload,
            headers=_internal_headers(),
        )

    handshake_end = time.perf_counter()

    handshake_response.raise_for_status()

    server_handshake = ServerHandshakeResponse(**handshake_response.json())

    measurements["client_to_server_handshake_http_ms"] = round(
        (handshake_end - handshake_start) * 1000,
        3,
    )
    measurements.update(server_handshake.measurements)

    steps.append("Client received server certificate and ephemeral ML-KEM public key.")

    steps.extend(server_handshake.steps)

    steps.append("Client verifies the server certificate against the configured CA.")

    verification = verify_certificate_against_ca(
        peer_certificate_pem=server_handshake.server_certificate_pem,
        ca_certificate_pem=ca_certificate_pem,
        expected_subject_fragment=expected_server_subject,
    )

    for key, value in verification.get("measurements", {}).items():
        measurements[f"client_server_certificate_{key}"] = value

    if not verification["verified"]:
        steps.append("Client stopped because server certificate verification failed.")

        total_end = time.perf_counter()

        measurements["client_encrypted_request_total_ms"] = round(
            (total_end - total_start) * 1000,
            3,
        )

        return {
            "encrypted_request_completed": False,
            "request_encrypted_by_client": False,
            "request_decrypted_by_server": False,
            "client_verified_server_certificate": False,
            "server_verified_client_certificate": False,
            "reason": (
                "The client rejected the server handshake because the server "
                "certificate could not be verified."
            ),
            "client_service": {
                "service_name": settings.SERVICE_NAME,
                "service_id": identity.get("service_id", settings.SERVICE_ID),
                "service_role": identity.get("service_role", settings.SERVICE_ROLE),
                "server_service_url": server_service_url,
                "identity_configured": True,
            },
            "server_handshake": {
                "handshake_started": server_handshake.handshake_started,
                "session_id": server_handshake.session_id,
                "kem_algorithm": server_handshake.kem_algorithm,
                "kem_public_key_received": bool(server_handshake.kem_public_key_b64),
                "server_certificate_received": bool(server_handshake.server_certificate_pem),
                "server_service": server_handshake.server_service,
            },
            "certificate_verification": {
                "client_verified_server": verification,
                "server_verified_client": {},
            },
            "kem": {
                "algorithm": server_handshake.kem_algorithm,
                "shared_secret_established": False,
            },
            "encryption": {
                "algorithm": "AES-256-GCM",
                "request_encrypted": False,
                "request_decrypted": False,
            },
            "server_response": {},
            "steps": steps,
            "measurements": measurements,
        }

    steps.append("Client verified the server certificate successfully.")
    steps.append("Client encapsulates a shared secret using the server ML-KEM public key.")

    shared_secret, kem_ciphertext_b64, kem_metrics = encapsulate_shared_secret(
        kem_algorithm=server_handshake.kem_algorithm,
        kem_public_key_b64=server_handshake.kem_public_key_b64,
    )
    measurements.update(kem_metrics)

    steps.append("Client derives an AES-256-GCM key using HKDF.")

    aes_key, hkdf_metrics = derive_aes_gcm_key(shared_secret)
    measurements.update(hkdf_metrics)

    aad_metadata = {
        "session_id": server_handshake.session_id,
        "operation": request.operation,
        "client_service_id": identity.get("service_id", settings.SERVICE_ID),
        "server_service_id": server_handshake.server_service.get("service_id"),
        "kem_algorithm": server_handshake.kem_algorithm,
        "encryption_algorithm": "AES-256-GCM",
    }

    steps.append("Client encrypts the application payload with AES-GCM.")

    encrypted_payload, encryption_metrics = encrypt_payload_with_aes_gcm(
        aes_key=aes_key,
        payload=request.payload,
        aad_metadata=aad_metadata,
    )
    measurements.update(encryption_metrics)

    steps.append("Client sends the encrypted request to the server secure endpoint.")

    secure_endpoint_payload = {
        "session_id": server_handshake.session_id,
        "client_certificate_pem": own_certificate_pem,
        "kem_algorithm": server_handshake.kem_algorithm,
        "kem_ciphertext_b64": kem_ciphertext_b64,
        "encryption_algorithm": "AES-256-GCM",
        "nonce_b64": encrypted_payload["nonce_b64"],
        "aad_b64": encrypted_payload["aad_b64"],
        "encrypted_payload_b64": encrypted_payload["encrypted_payload_b64"],
        "metadata": {
            "operation": request.operation,
            "client_service_id": identity.get("service_id", settings.SERVICE_ID),
            "purpose": "encrypted service-to-service request demo",
        },
    }

    secure_call_start = time.perf_counter()

    async with httpx.AsyncClient(timeout=60.0) as client:
        secure_response = await client.post(
            f"{server_service_url.rstrip('/')}/server/secure-endpoint",
            json=secure_endpoint_payload,
            headers=_internal_headers(),
        )

    secure_call_end = time.perf_counter()

    secure_response.raise_for_status()

    server_response = ServerSecureEndpointResponse(**secure_response.json())

    measurements["client_to_server_secure_endpoint_http_ms"] = round(
        (secure_call_end - secure_call_start) * 1000,
        3,
    )
    measurements.update(server_response.measurements)

    steps.extend(server_response.steps)
    steps.append("Client received the server processing result.")

    total_end = time.perf_counter()

    measurements["client_encrypted_request_total_ms"] = round(
        (total_end - total_start) * 1000,
        3,
    )

    encrypted_request_completed = bool(
        verification["verified"]
        and server_response.secure_request_processed
        and server_response.request_decrypted_by_server
        and server_response.server_verified_client_certificate
    )

    if encrypted_request_completed:
        reason = (
            "Encrypted request completed successfully. The client verified the "
            "server certificate, established a shared secret with ML-KEM, "
            "encrypted the payload with AES-GCM and the server decrypted it."
        )
    else:
        reason = (
            "Encrypted request did not complete successfully. Check certificate "
            "verification, KEM and server decryption details."
        )

    return {
        "encrypted_request_completed": encrypted_request_completed,
        "request_encrypted_by_client": True,
        "request_decrypted_by_server": bool(server_response.request_decrypted_by_server),
        "client_verified_server_certificate": bool(verification["verified"]),
        "server_verified_client_certificate": bool(
            server_response.server_verified_client_certificate
        ),
        "reason": reason,
        "client_service": {
            "service_name": settings.SERVICE_NAME,
            "service_id": identity.get("service_id", settings.SERVICE_ID),
            "service_role": identity.get("service_role", settings.SERVICE_ROLE),
            "server_service_url": server_service_url,
            "identity_configured": True,
            "expected_server_subject": expected_server_subject,
        },
        "server_handshake": {
            "handshake_started": server_handshake.handshake_started,
            "session_id": server_handshake.session_id,
            "kem_algorithm": server_handshake.kem_algorithm,
            "kem_public_key_received": bool(server_handshake.kem_public_key_b64),
            "server_certificate_received": bool(server_handshake.server_certificate_pem),
            "server_service": server_handshake.server_service,
        },
        "certificate_verification": {
            "client_verified_server": verification,
            "server_verified_client": server_response.client_certificate_verification,
        },
        "kem": {
            "algorithm": server_handshake.kem_algorithm,
            "shared_secret_established": True,
            "ciphertext_sent_to_server": True,
            "session_id": server_handshake.session_id,
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "request_encrypted": True,
            "request_decrypted": bool(server_response.request_decrypted_by_server),
            "aad_authenticated": True,
            "nonce_generated": True,
        },
        "server_response": server_response.model_dump(),
        "steps": steps,
        "measurements": measurements,
    }