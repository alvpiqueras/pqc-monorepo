from __future__ import annotations

import time
from typing import Any, Dict

import httpx

from core.config import settings
from models.demo_models import (
    EncryptedRequestDemoRequest,
    HandshakeDemoRequest,
)


APPLICATION_LEVEL_MTLS_SCOPE_NOTE = (
    "This is not native PQC TLS termination. The demo runs over real HTTP "
    "service-to-service calls, while mTLS-like authentication, certificate "
    "verification, post-quantum key establishment and payload protection are "
    "implemented at application level."
)


def _internal_headers() -> dict[str, str]:
    return {
        "X-MTLS-Demo-Token": settings.INTERNAL_DEMO_TOKEN,
    }


async def run_handshake_demo(
    request: HandshakeDemoRequest,
) -> Dict[str, Any]:
    """
    Run the handshake demo from the gateway perspective.

    The gateway does not perform the cryptographic handshake itself. It asks the
    client service to initiate the handshake with the server service and returns
    the result to the caller.
    """

    total_start = time.perf_counter()

    steps: list[str] = [
        "Gateway received a handshake demo request.",
        "Gateway forwards the request to the client service.",
    ]

    client_payload = {
        "operation": request.operation,
        "payload": request.payload,
    }

    client_start = time.perf_counter()

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{settings.CLIENT_SERVICE_URL.rstrip('/')}/client/secure-call/handshake",
            json=client_payload,
            headers=_internal_headers(),
        )

    client_end = time.perf_counter()

    response.raise_for_status()

    client_result = response.json()

    steps.extend(client_result.get("steps", []))
    steps.append("Gateway received the handshake result from the client service.")

    total_end = time.perf_counter()

    measurements = {
        "gateway_to_client_handshake_http_ms": round(
            (client_end - client_start) * 1000,
            3,
        ),
        "gateway_total_handshake_demo_ms": round(
            (total_end - total_start) * 1000,
            3,
        ),
    }

    measurements.update(client_result.get("measurements", {}))

    handshake_completed = bool(client_result.get("handshake_completed"))

    if handshake_completed:
        reason = (
            "Handshake completed successfully. The client contacted the server, "
            "received an ephemeral ML-KEM public key and verified the server certificate."
        )
    else:
        reason = "Handshake did not complete successfully."

    return {
        "handshake_completed": handshake_completed,
        "reason": reason,
        "scope_note": APPLICATION_LEVEL_MTLS_SCOPE_NOTE,
        "client_service": client_result.get("client_service", {}),
        "server_handshake": client_result.get("server_handshake", {}),
        "certificate_verification": client_result.get(
            "certificate_verification",
            {},
        ),
        "steps": steps,
        "measurements": measurements,
        "raw_client_response": client_result,
    }


async def run_encrypted_request_demo(
    request: EncryptedRequestDemoRequest,
) -> Dict[str, Any]:
    """
    Run the encrypted request demo from the gateway perspective.

    The gateway asks the client service to:
    - start a handshake with the server;
    - verify the server certificate;
    - establish a shared secret with ML-KEM;
    - encrypt the payload with AES-GCM;
    - send the encrypted request to the server.
    """

    total_start = time.perf_counter()

    steps: list[str] = [
        "Gateway received an encrypted request demo.",
        "Gateway forwards the encrypted request demo to the client service.",
    ]

    client_payload = {
        "operation": request.operation,
        "payload": request.payload,
    }

    client_start = time.perf_counter()

    async with httpx.AsyncClient(timeout=90.0) as client:
        response = await client.post(
            f"{settings.CLIENT_SERVICE_URL.rstrip('/')}/client/secure-call/encrypted-request",
            json=client_payload,
            headers=_internal_headers(),
        )

    client_end = time.perf_counter()

    response.raise_for_status()

    client_result = response.json()

    steps.extend(client_result.get("steps", []))
    steps.append("Gateway received the encrypted request result from the client service.")

    total_end = time.perf_counter()

    measurements = {
        "gateway_to_client_encrypted_request_http_ms": round(
            (client_end - client_start) * 1000,
            3,
        ),
        "gateway_total_encrypted_request_demo_ms": round(
            (total_end - total_start) * 1000,
            3,
        ),
    }

    measurements.update(client_result.get("measurements", {}))

    encrypted_request_completed = bool(
        client_result.get("encrypted_request_completed")
    )

    if encrypted_request_completed:
        reason = (
            "Encrypted request completed successfully. The client verified the "
            "server certificate, established a shared secret with ML-KEM, "
            "encrypted the application payload with AES-GCM and the server decrypted it."
        )
    else:
        reason = (
            "Encrypted request did not complete successfully. Check certificate "
            "verification, ML-KEM and AES-GCM processing details."
        )

    return {
        "encrypted_request_completed": encrypted_request_completed,
        "request_encrypted_by_client": bool(
            client_result.get("request_encrypted_by_client")
        ),
        "request_decrypted_by_server": bool(
            client_result.get("request_decrypted_by_server")
        ),
        "client_verified_server_certificate": bool(
            client_result.get("client_verified_server_certificate")
        ),
        "server_verified_client_certificate": bool(
            client_result.get("server_verified_client_certificate")
        ),
        "reason": reason,
        "scope_note": APPLICATION_LEVEL_MTLS_SCOPE_NOTE,
        "client_service": client_result.get("client_service", {}),
        "server_handshake": client_result.get("server_handshake", {}),
        "certificate_verification": client_result.get(
            "certificate_verification",
            {},
        ),
        "kem": client_result.get("kem", {}),
        "encryption": client_result.get("encryption", {}),
        "server_response": client_result.get("server_response", {}),
        "steps": steps,
        "measurements": measurements,
        "raw_client_response": client_result,
    }