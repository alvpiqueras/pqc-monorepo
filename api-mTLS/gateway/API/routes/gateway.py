from fastapi import APIRouter, HTTPException

from core.config import settings
from models.gateway_models import ConnectivityCheckResponse
from services.orchestration_service import check_distributed_connectivity


router = APIRouter(
    prefix="/mtls",
)


@router.get(
    "/info",
    tags=["mTLS Distributed - Overview"],
)
def mtls_gateway_info():
    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "component_role": settings.COMPONENT_ROLE,
        "architecture": {
            "gateway": "Public orchestration API used by the frontend.",
            "client_service": "Internal service initiating the secure call.",
            "server_service": "Internal service receiving the secure call.",
            "internal_ca": "External internal CA service issuing PQC X.509 certificates.",
        },
    }


@router.get(
    "/scenario",
    tags=["mTLS Distributed - Overview"],
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
            "gateway_api": "Orchestrates the demo and exposes a frontend-friendly API.",
            "client_service": "Initiates the protected service-to-service call.",
            "server_service": "Receives and processes the protected call.",
            "internal_ca": "Issues PQC X.509 certificates used for mutual authentication.",
        },
        "planned_flow": [
            "Gateway requests certificates from internal-ca.",
            "Gateway configures client-service and server-service identities.",
            "Client-service initiates a real HTTP call to server-service.",
            "Both services verify each other's certificates at application level.",
            "ML-KEM establishes a shared secret.",
            "AES-GCM protects the request and response payloads.",
        ],
        "scope_note": (
            "This is not native TLS termination with PQC certificates. It is a "
            "distributed application-level simulation of mTLS-like trust and "
            "secure exchange using real service-to-service HTTP calls."
        ),
    }


@router.get(
    "/connectivity",
    response_model=ConnectivityCheckResponse,
    tags=["mTLS Distributed - Connectivity"],
)
async def mtls_connectivity_check():
    try:
        return await check_distributed_connectivity()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))