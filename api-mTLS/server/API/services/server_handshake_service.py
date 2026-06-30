from __future__ import annotations

import time
from typing import Any, Dict

from core.config import settings
from models.handshake_models import ServerHandshakeStartRequest
from services.server_identity_service import require_configured_server_identity
from services.server_session_service import create_kem_handshake_session


def start_server_handshake(
    request: ServerHandshakeStartRequest,
) -> Dict[str, Any]:
    """
    Start Phase C1 from the server perspective.

    The server:
    - checks that its identity was configured during bootstrap;
    - creates an ephemeral ML-KEM session;
    - returns its own certificate and KEM public key to the client.
    """

    total_start = time.perf_counter()

    steps: list[str] = [
        "Server received a Phase C1 handshake start request from the client.",
        "Server checks that its identity was configured during bootstrap.",
    ]

    identity = require_configured_server_identity()

    steps.append("Server identity is configured.")
    steps.append("Server creates an ephemeral ML-KEM handshake session.")

    session, session_metrics = create_kem_handshake_session(
        settings.DEFAULT_KEM_ALGORITHM
    )

    steps.append("Server generated an ephemeral ML-KEM key pair.")
    steps.append("Server stores the temporary handshake session in memory.")
    steps.append("Server returns its certificate and ML-KEM public key to the client.")

    certificate_metadata = identity.get("certificate_metadata", {})

    total_end = time.perf_counter()

    measurements = {
        "server_total_handshake_start_ms": round(
            (total_end - total_start) * 1000,
            3,
        )
    }

    measurements.update(session_metrics)

    return {
        "handshake_started": True,
        "session_id": session["session_id"],
        "kem_algorithm": session["kem_algorithm"],
        "kem_public_key_b64": session["kem_public_key_b64"],
        "server_certificate_pem": identity["own_certificate_pem"],
        "server_service": {
            "service_name": settings.SERVICE_NAME,
            "service_id": identity.get("service_id", settings.SERVICE_ID),
            "service_role": identity.get("service_role", settings.SERVICE_ROLE),
            "identity_configured": True,
            "expected_client_subject": identity.get("expected_client_subject"),
            "certificate_subject": certificate_metadata.get("certificate_subject"),
            "certificate_issuer": certificate_metadata.get("certificate_issuer"),
            "certificate_dates": certificate_metadata.get("certificate_dates"),
            "requested_operation": request.operation,
            "request_phase": request.phase,
            "client_service_id": request.client_service_id,
        },
        "steps": steps,
        "measurements": measurements,
    }