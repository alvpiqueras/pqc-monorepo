from fastapi import APIRouter, HTTPException

from core.config import settings
from models.gateway_models import ConnectivityCheckResponse
from services.orchestration_service import check_distributed_connectivity


router = APIRouter(
    prefix="/mtls",
)


@router.get(
    "/info",
    tags=["API mTLS Overview"],
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
            "client": "Service that initiates the secure service-to-service call.",
            "server": "Service that receives and processes the secure call.",
            "internal_ca": "Internal CA API that issues PQC X.509 certificates.",
        },
        "configured_urls": {
            "internal_ca_url": settings.INTERNAL_CA_URL,
            "client_service_url": settings.CLIENT_SERVICE_URL,
            "server_service_url": settings.SERVER_SERVICE_URL,
        },
    }


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
        "planned_flow": [
            "Gateway requests certificates from internal-ca.",
            "Gateway configures client and server identities.",
            "Client initiates a real HTTP call to server.",
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
    tags=["Connectivity"],
)
async def mtls_connectivity_check():
    try:
        return await check_distributed_connectivity()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))