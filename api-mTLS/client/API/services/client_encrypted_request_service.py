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
    decrypt_payload_with_aes_gcm,
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
    Run the full secure service-to-service call from the client perspective.

    The client:
    - starts a handshake with the server;
    - verifies the server certificate;
    - encapsulates a shared secret with ML-KEM;
    - derives an AES-GCM key with HKDF;
    - encrypts the request payload;
    - sends it to the server secure endpoint;
    - receives an encrypted response;
    - decrypts the server response using the same AES-GCM session key.
    """

    total_start = time.perf_counter()

    steps: list[str] = [
        "Client received a secure service-to-service call request from the gateway.",
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
        "phase": "secure-call",
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

        measurements["client_secure_call_total_ms"] = round(
            (total_end - total_start) * 1000,
            3,
        )

        return {
            "secure_call_completed": False,
            "encrypted_request_completed": False,
            "request_encrypted_by_client": False,
            "request_decrypted_by_server": False,
            "response_encrypted_by_server": False,
            "response_decrypted_by_client": False,
            "client_verified_server_certificate": False,
            "server_verified_client_certificate": False,
            "reason": (
                "The client rejected the server handshake because the server "
                "certificate could not be verified."
            ),
            "decrypted_server_response": None,
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
                "response_encrypted": False,
                "response_decrypted": False,
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

    request_aad_metadata = {
        "session_id": server_handshake.session_id,
        "operation": request.operation,
        "client_service_id": identity.get("service_id", settings.SERVICE_ID),
        "server_service_id": server_handshake.server_service.get("service_id"),
        "kem_algorithm": server_handshake.kem_algorithm,
        "encryption_algorithm": "AES-256-GCM",
        "direction": "client-to-server",
    }

    steps.append("Client encrypts the application request payload with AES-GCM.")

    encrypted_payload, encryption_metrics = encrypt_payload_with_aes_gcm(
        aes_key=aes_key,
        payload=request.payload,
        aad_metadata=request_aad_metadata,
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
            "purpose": "secure service-to-service call demo",
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
    steps.append("Client received the encrypted server response.")

    response_decrypted_by_client = False
    decrypted_server_response = None

    if server_response.response_encrypted_by_server:
        steps.append("Client decrypts the encrypted server response with AES-GCM.")

        if not server_response.encrypted_response_b64:
            raise ValueError("Server response is missing encrypted_response_b64.")

        if not server_response.response_nonce_b64:
            raise ValueError("Server response is missing response_nonce_b64.")

        if not server_response.response_aad_b64:
            raise ValueError("Server response is missing response_aad_b64.")

        decrypted_server_response, response_decrypt_metrics = decrypt_payload_with_aes_gcm(
            aes_key=aes_key,
            nonce_b64=server_response.response_nonce_b64,
            aad_b64=server_response.response_aad_b64,
            encrypted_payload_b64=server_response.encrypted_response_b64,
        )
        measurements.update(response_decrypt_metrics)

        response_decrypted_by_client = True
        steps.append("Client decrypted the server response successfully.")

    else:
        steps.append("Server did not return an encrypted response.")

    total_end = time.perf_counter()

    measurements["client_secure_call_total_ms"] = round(
        (total_end - total_start) * 1000,
        3,
    )

    secure_call_completed = bool(
        verification["verified"]
        and server_response.secure_request_processed
        and server_response.request_decrypted_by_server
        and server_response.server_verified_client_certificate
        and server_response.response_encrypted_by_server
        and response_decrypted_by_client
    )

    encrypted_request_completed = bool(
        verification["verified"]
        and server_response.secure_request_processed
        and server_response.request_decrypted_by_server
        and server_response.server_verified_client_certificate
    )

    if secure_call_completed:
        reason = (
            "Secure call completed successfully. The client verified the server "
            "certificate, established a shared secret with ML-KEM, encrypted the "
            "request with AES-GCM, the server decrypted it, encrypted the response "
            "and the client decrypted the response."
        )
    else:
        reason = (
            "Secure call did not complete successfully. Check certificate "
            "verification, ML-KEM, request encryption and response decryption details."
        )

    return {
        "secure_call_completed": secure_call_completed,
        "encrypted_request_completed": encrypted_request_completed,
        "request_encrypted_by_client": True,
        "request_decrypted_by_server": bool(server_response.request_decrypted_by_server),
        "response_encrypted_by_server": bool(server_response.response_encrypted_by_server),
        "response_decrypted_by_client": response_decrypted_by_client,
        "client_verified_server_certificate": bool(verification["verified"]),
        "server_verified_client_certificate": bool(
            server_response.server_verified_client_certificate
        ),
        "reason": reason,
        "decrypted_server_response": decrypted_server_response,
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
            "response_encrypted": bool(server_response.response_encrypted_by_server),
            "response_decrypted": response_decrypted_by_client,
            "request_aad_authenticated": True,
            "response_aad_authenticated": response_decrypted_by_client,
            "request_nonce_generated": True,
            "response_nonce_received": bool(server_response.response_nonce_b64),
        },
        "server_response": server_response.model_dump(),
        "steps": steps,
        "measurements": measurements,
    }