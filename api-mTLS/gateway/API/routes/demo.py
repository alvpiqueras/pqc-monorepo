from fastapi import APIRouter, HTTPException

from models.demo_models import (
    HandshakeDemoRequest,
    HandshakeDemoResponse,
)
from services.demo_service import (
    PHASE_C_SCOPE_NOTE,
    run_handshake_demo,
)


router = APIRouter(
    prefix="/mtls/demo",
)


@router.get(
    "/info",
    tags=["Demo"],
)
def demo_info():
    return {
        "title": "Distributed mTLS-like Secure Call Demo",
        "phase": "Phase C",
        "current_subphase": "Phase C1 - Handshake and server certificate verification",
        "scope_note": PHASE_C_SCOPE_NOTE,
        "important_clarification": {
            "not_native_tls": True,
            "explanation": (
                "This API does not replace the native TLS handshake performed by "
                "the HTTP runtime. Instead, it demonstrates the same security ideas "
                "at application level: service identities, mutual certificate "
                "verification, post-quantum key establishment and authenticated "
                "encryption over real service-to-service HTTP calls."
            ),
        },
        "phase_c1_flow": [
            "Gateway receives a frontend-friendly demo request.",
            "Gateway asks the client service to start the handshake.",
            "Client checks that its identity was configured during bootstrap.",
            "Client calls server /server/handshake/start.",
            "Server checks that its identity was configured during bootstrap.",
            "Server creates a temporary handshake session.",
            "Server generates an ephemeral ML-KEM public key.",
            "Server returns its certificate, session_id and ML-KEM public key.",
            "Client verifies the server certificate against the configured CA.",
            "Client checks that the server certificate subject matches the expected server identity.",
            "Gateway returns the result, steps and measurements.",
        ],
        "not_done_in_phase_c1": [
            "No ML-KEM encapsulation is performed yet.",
            "No shared secret is established yet.",
            "No AES-GCM encryption is performed yet.",
            "No protected application payload is sent yet.",
        ],
        "next_subphases": {
            "phase_c2": (
                "Client encapsulates a shared secret using the server ML-KEM public key "
                "and sends an AES-GCM encrypted request to the server."
            ),
            "phase_c3": (
                "Server encrypts the response and the client decrypts it before "
                "returning the final result to the gateway."
            ),
        },
    }


@router.post(
    "/handshake",
    response_model=HandshakeDemoResponse,
    tags=["Demo"],
)
async def handshake_demo_endpoint(
    request: HandshakeDemoRequest,
):
    try:
        return await run_handshake_demo(request)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )