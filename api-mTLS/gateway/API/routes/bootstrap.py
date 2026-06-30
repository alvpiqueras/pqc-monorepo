from fastapi import APIRouter, HTTPException

from models.bootstrap_models import (
    BootstrapFromInternalCaRequest,
    BootstrapFromInternalCaResponse,
    BootstrapStatusResponse,
)
from services.bootstrap_service import (
    bootstrap_from_internal_ca,
    get_bootstrap_status,
)


router = APIRouter(
    prefix="/mtls/bootstrap",
)


@router.get(
    "/info",
    tags=["Bootstrap"],
)
def bootstrap_info():
    return {
        "title": "Bootstrap Distributed mTLS from Internal CA",
        "purpose": (
            "Configure the distributed mTLS demo by requesting real PQC X.509 "
            "certificates from internal-ca and installing them into the client "
            "and server services."
        ),
        "flow": [
            "Gateway calls internal-ca to generate an internal CA.",
            "Gateway requests a CSR for the client service.",
            "Gateway requests a certificate for the client service.",
            "Gateway requests a CSR for the server service.",
            "Gateway requests a certificate for the server service.",
            "Gateway configures the client service identity.",
            "Gateway configures the server service identity.",
            "Gateway checks that both services are ready for the secure exchange phase.",
        ],
        "uses_internal_ca": True,
        "internal_ca_dependency": (
            "The gateway expects internal-ca to expose /ca/generate, "
            "/ca/csr/generate and /ca/certificate/issue."
        ),
        "scope_note": (
            "This phase configures identities. It does not yet perform the "
            "distributed secure service-to-service exchange."
        ),
    }


@router.post(
    "/from-internal-ca",
    response_model=BootstrapFromInternalCaResponse,
    tags=["Bootstrap"],
)
async def bootstrap_from_internal_ca_endpoint(
    request: BootstrapFromInternalCaRequest,
):
    try:
        return await bootstrap_from_internal_ca(request)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get(
    "/status",
    response_model=BootstrapStatusResponse,
    tags=["Bootstrap"],
)
async def bootstrap_status_endpoint():
    try:
        return await get_bootstrap_status()

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )