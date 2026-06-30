from fastapi import APIRouter, HTTPException

from models.demo_models import (
    EncryptedRequestDemoRequest,
    EncryptedRequestDemoResponse,
    HandshakeDemoRequest,
    HandshakeDemoResponse,
    SecureCallDemoRequest,
    SecureCallDemoResponse,
)
from services.demo_service import (
    APPLICATION_LEVEL_MTLS_SCOPE_NOTE,
    run_encrypted_request_demo,
    run_handshake_demo,
    run_secure_call_demo,
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
        "title": "Distributed mTLS-like Secure Service-to-Service Demo",
        "scope_note": APPLICATION_LEVEL_MTLS_SCOPE_NOTE,
        "important_clarification": {
            "not_native_tls": True,
            "explanation": (
                "This API does not replace the native TLS handshake performed by "
                "the HTTP runtime. Instead, it demonstrates the same security "
                "ideas at application level: service identities, certificate "
                "verification, post-quantum key establishment and authenticated "
                "encryption over real service-to-service HTTP calls."
            ),
        },
        "available_steps": {
            "handshake": {
                "endpoint": "POST /mtls/demo/handshake",
                "summary": (
                    "The gateway asks the client to start a handshake with the "
                    "server. The server returns its certificate and an ephemeral "
                    "ML-KEM public key. The client verifies the server certificate."
                ),
            },
            "encrypted_request": {
                "endpoint": "POST /mtls/demo/encrypted-request",
                "summary": (
                    "The gateway asks the client to establish a shared secret with "
                    "the server using ML-KEM, encrypt an application payload with "
                    "AES-GCM and send it to the server secure endpoint."
                ),
            },
            "secure_call": {
                "endpoint": "POST /mtls/demo/secure-call",
                "summary": (
                    "The gateway asks the client to perform the complete secure "
                    "service-to-service exchange: encrypted request, server "
                    "decryption, encrypted response and client decryption."
                ),
            },
        },
        "secure_call_flow": [
            "Gateway receives a frontend-friendly request.",
            "Gateway asks the client service to perform the secure call.",
            "Client starts a handshake with the server.",
            "Server returns its certificate and an ephemeral ML-KEM public key.",
            "Client verifies the server certificate against the configured CA.",
            "Client encapsulates a shared secret using the server ML-KEM public key.",
            "Client derives an AES-256-GCM key using HKDF.",
            "Client encrypts the application request payload with AES-GCM.",
            "Client sends the encrypted request and its certificate to the server.",
            "Server verifies the client certificate against the configured CA.",
            "Server decapsulates the ML-KEM ciphertext.",
            "Server derives the same AES-256-GCM key using HKDF.",
            "Server decrypts the protected request payload.",
            "Server processes the application request.",
            "Server encrypts the application response with AES-GCM.",
            "Client decrypts the encrypted server response.",
            "Gateway returns the final result, steps and measurements.",
        ],
        "security_mapping": {
            "ML-DSA": (
                "Used by internal-ca for PQC X.509 certificate signatures and service identity."
            ),
            "ML-KEM": (
                "Used by the service-to-service demo for post-quantum session establishment."
            ),
            "AES-GCM": (
                "Used for authenticated encryption of application request and response payloads."
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


@router.post(
    "/encrypted-request",
    response_model=EncryptedRequestDemoResponse,
    tags=["Demo"],
)
async def encrypted_request_demo_endpoint(
    request: EncryptedRequestDemoRequest,
):
    try:
        return await run_encrypted_request_demo(request)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.post(
    "/secure-call",
    response_model=SecureCallDemoResponse,
    tags=["Demo"],
)
async def secure_call_demo_endpoint(
    request: SecureCallDemoRequest,
):
    try:
        return await run_secure_call_demo(request)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )