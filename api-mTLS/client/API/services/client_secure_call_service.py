from __future__ import annotations

import base64
import time
from typing import Any, Dict

import httpx

from core.config import settings
from models.secure_call_models import ClientHandshakeRequest, ServerHandshakeResponse
from services.certificate_verification_service import verify_certificate_against_ca
from services.client_identity_service import require_configured_client_identity


def _internal_headers() -> dict[str, str]:
    return {
        "X-MTLS-Demo-Token": settings.INTERNAL_DEMO_TOKEN,
    }


def _base64_size_bytes(value: str) -> int | None:
    try:
        return len(base64.b64decode(value))
    except Exception:
        return None


async def run_client_handshake(
    request: ClientHandshakeRequest,
) -> Dict[str, Any]:
    """
    Run Phase C1 from the client perspective.

    The client:
    - checks that its identity was configured in Phase B;
    - asks the server to start a handshake;
    - receives the server certificate and ephemeral ML-KEM public key;
    - verifies the server certificate against the configured CA.
    """

    total_start = time.perf_counter()

    steps: list[str] = [
        "Client received a Phase C1 handshake request from the gateway.",
        "Client checks that its identity was configured during bootstrap.",
    ]

    identity = require_configured_client_identity()

    ca_certificate_pem = identity["ca_certificate_pem"]
    expected_server_subject = identity["expected_server_subject"]
    server_service_url = identity.get("server_service_url") or settings.SERVER_SERVICE_URL

    steps.append("Client identity is configured.")
    steps.append("Client contacts the server to start the handshake.")

    server_payload = {
        "operation": request.operation,
        "payload": request.payload,
        "client_service_id": identity.get("service_id", settings.SERVICE_ID),
        "phase": "C1-handshake-only",
    }

    server_start = time.perf_counter()

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{server_service_url.rstrip('/')}/server/handshake/start",
            json=server_payload,
            headers=_internal_headers(),
        )

    server_end = time.perf_counter()

    response.raise_for_status()

    server_handshake = ServerHandshakeResponse(**response.json())

    steps.append("Client received handshake material from the server.")

    steps.extend(server_handshake.steps)

    steps.append("Client verifies the server certificate against the configured CA.")

    verification_start = time.perf_counter()

    certificate_verification = verify_certificate_against_ca(
        peer_certificate_pem=server_handshake.server_certificate_pem,
        ca_certificate_pem=ca_certificate_pem,
        expected_subject_fragment=expected_server_subject,
    )

    verification_end = time.perf_counter()

    if certificate_verification["verified"]:
        steps.append("Client verified the server certificate successfully.")
    else:
        steps.append("Client could not verify the server certificate successfully.")

    kem_public_key_size_bytes = _base64_size_bytes(
        server_handshake.kem_public_key_b64
    )

    handshake_completed = bool(
        server_handshake.handshake_started
        and server_handshake.session_id
        and server_handshake.kem_public_key_b64
        and certificate_verification["verified"]
    )

    if handshake_completed:
        reason = (
            "Phase C1 completed successfully. The client received the server "
            "certificate, verified it against the configured CA and obtained an "
            "ephemeral ML-KEM public key for the next phase."
        )
    else:
        reason = (
            "Phase C1 did not complete successfully. Check server handshake data "
            "and certificate verification details."
        )

    total_end = time.perf_counter()

    measurements = {
        "client_to_server_handshake_http_ms": round(
            (server_end - server_start) * 1000,
            3,
        ),
        "client_certificate_verification_step_ms": round(
            (verification_end - verification_start) * 1000,
            3,
        ),
        "client_total_handshake_ms": round(
            (total_end - total_start) * 1000,
            3,
        ),
    }

    measurements.update(server_handshake.measurements)

    for key, value in certificate_verification.get("measurements", {}).items():
        measurements[f"client_{key}"] = value

    return {
        "handshake_completed": handshake_completed,
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
            "kem_public_key_size_bytes": kem_public_key_size_bytes,
            "server_certificate_received": bool(server_handshake.server_certificate_pem),
            "server_service": server_handshake.server_service,
        },
        "certificate_verification": certificate_verification,
        "steps": steps,
        "measurements": measurements,
    }