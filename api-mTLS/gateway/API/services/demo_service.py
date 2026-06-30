from __future__ import annotations

import time
from typing import Any, Dict

import httpx

from core.config import settings
from models.demo_models import HandshakeDemoRequest


PHASE_C_SCOPE_NOTE = (
    "This is not native PQC TLS termination. The demo performs an "
    "application-level mTLS-like handshake over real HTTP service-to-service "
    "calls. PQC X.509 certificates are used as application-level identities, "
    "and the ML-KEM material prepared in the handshake will be used by later "
    "phases to establish an encrypted session."
)


def _internal_headers() -> dict[str, str]:
    return {
        "X-MTLS-Demo-Token": settings.INTERNAL_DEMO_TOKEN,
    }


async def run_handshake_demo(
    request: HandshakeDemoRequest,
) -> Dict[str, Any]:
    """
    Run Phase C1 from the gateway perspective.

    The gateway does not perform the cryptographic handshake itself. It asks the
    client service to initiate the handshake with the server service and returns
    the result to the caller.
    """

    total_start = time.perf_counter()

    steps: list[str] = [
        "Gateway received a Phase C1 handshake demo request.",
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
    steps.append("Gateway received the Phase C1 result from the client service.")

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
            "Phase C1 completed successfully. The client contacted the server, "
            "received an ephemeral ML-KEM public key and verified the server certificate."
        )
    else:
        reason = "Phase C1 did not complete successfully."

    return {
        "handshake_completed": handshake_completed,
        "reason": reason,
        "scope_note": PHASE_C_SCOPE_NOTE,
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