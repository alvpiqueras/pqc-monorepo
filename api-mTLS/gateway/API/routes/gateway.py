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
                "Used in later phases for authenticated encryption of application payloads."
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