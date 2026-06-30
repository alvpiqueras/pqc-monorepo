from fastapi import APIRouter, Header, HTTPException

from core.config import settings
from models.client_models import (
    ClientIdentityStatusResponse,
    ConfigureClientIdentityRequest,
    ConfigureClientIdentityResponse,
)
from services.client_identity_service import (
    configure_client_identity,
    get_client_identity_status,
)


router = APIRouter(
    prefix="/client",
)


def _require_internal_token(token: str | None) -> None:
    if token != settings.INTERNAL_DEMO_TOKEN:
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing internal demo token.",
        )


@router.get(
    "/info",
    tags=["Overview"],
)
def client_info(
    x_qcs_demo_token: str | None = Header(default=None),
):
    _require_internal_token(x_qcs_demo_token)

    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "service_id": settings.SERVICE_ID,
        "service_role": settings.SERVICE_ROLE,
        "server_service_url": settings.SERVER_SERVICE_URL,
        "status": "running",
        "identity_configured": get_client_identity_status()["configured"],
    }


@router.post(
    "/configure-identity",
    response_model=ConfigureClientIdentityResponse,
    tags=["Identity"],
)
def configure_identity(
    request: ConfigureClientIdentityRequest,
    x_qcs_demo_token: str | None = Header(default=None),
):
    """
    Configure the client service with the certificate material obtained by the gateway.

    This endpoint is intended to be called by the gateway during bootstrap.
    """

    _require_internal_token(x_qcs_demo_token)

    try:
        return configure_client_identity(request)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@router.get(
    "/identity/status",
    response_model=ClientIdentityStatusResponse,
    tags=["Identity"],
)
def identity_status(
    x_qcs_demo_token: str | None = Header(default=None),
):
    """
    Return the current in-memory identity configuration status.
    """

    _require_internal_token(x_qcs_demo_token)

    return get_client_identity_status()