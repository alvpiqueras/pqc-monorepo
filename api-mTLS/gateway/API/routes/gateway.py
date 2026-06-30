from fastapi import APIRouter, HTTPException

from core.config import settings
from models.gateway_models import ConnectivityCheckResponse
from services.orchestration_service import check_distributed_connectivity


router = APIRouter(
    prefix="/mtls",
)


@router.get(
    "/scenario",
    tags=["API mTLS Overview"],
)
def mtls_gateway_scenario():
    return {
        "title": "Distributed Application-Level mTLS with PQC Certificates",
        "summary": (
            "This API demonstrates a distributed service-to-service secure "
            "communication flow. A public gateway orchestrates two real backend "
            "services that communicate with each other and consume certificates "
            "issued by the internal PQC CA."
        ),
        "actors": {
            "gateway": "Orchestrates the demo and exposes a frontend-friendly API.",
            "client": "Initiates the protected service-to-service call.",
            "server": "Receives and processes the protected call.",
            "internal_ca": "Issues PQC X.509 certificates used for mutual authentication.",
        },
        "implemented_capabilities": {
            "distributed_services": (
                "Gateway, client and server services run as separate services and "
                "communicate through real HTTP calls."
            ),
            "identity_bootstrap": (
                "Gateway consumes internal-ca to issue PQC X.509 certificates and "
                "configure client/server identities."
            ),
            "handshake": (
                "Client initiates a real handshake with the server, receives an "
                "ephemeral ML-KEM public key and verifies the server certificate."
            ),
            "encrypted_request": (
                "Client establishes a shared secret with ML-KEM, encrypts an "
                "application payload with AES-GCM and sends it to the server."
            ),
            "encrypted_response": (
                "Server encrypts the application response with AES-GCM and the "
                "client decrypts it before returning the final result to the gateway."
            ),
        },
        "security_mapping": {
            "ML-DSA": (
                "Used by internal-ca for PQC X.509 certificate signatures and "
                "service identity."
            ),
            "ML-KEM": (
                "Used by the service-to-service demo for post-quantum session "
                "establishment."
            ),
            "AES-GCM": (
                "Used for authenticated encryption of application request and "
                "response payloads."
            ),
        },
        "scope_note": (
            "This is not native TLS termination with PQC certificates. The demo "
            "runs over real HTTP calls between distributed services, but the "
            "mTLS-like authentication, certificate verification, key establishment "
            "and payload protection are implemented at application level."
        ),
    }


@router.get(
    "/connectivity",
    response_model=ConnectivityCheckResponse,
    tags=["Connectivity"],
)
async def mtls_connectivity_check():
    try:
        return await check_distributed_connectivity()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))