from fastapi import APIRouter, Header, HTTPException

from core.config import settings
from models.server_models import (
    ConfigureServerIdentityRequest,
    ConfigureServerIdentityResponse,
    ServerIdentityStatusResponse,
)
from services.server_identity_service import (
    configure_server_identity,
    get_server_identity_status,
)


router = APIRouter(
    prefix="/server",
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
def server_info(
    x_mtls_demo_token: str | None = Header(default=None),
):
    _require_internal_token(x_mtls_demo_token)

    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "service_id": settings.SERVICE_ID,
        "service_role": settings.SERVICE_ROLE,
        "status": "running",
        "identity_configured": get_server_identity_status()["configured"],
    }


@router.post(
    "/configure-identity",
    response_model=ConfigureServerIdentityResponse,
    tags=["Identity"],
)
def configure_identity(
    request: ConfigureServerIdentityRequest,
    x_mtls_demo_token: str | None = Header(default=None),
):
    """
    Configure the server service with the certificate material obtained by the gateway.

    This endpoint is intended to be called by the gateway during bootstrap.
    """

    _require_internal_token(x_mtls_demo_token)

    try:
        return configure_server_identity(request)

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
    response_model=ServerIdentityStatusResponse,
    tags=["Identity"],
)
def identity_status(
    x_mtls_demo_token: str | None = Header(default=None),
):
    """
    Return the current in-memory identity configuration status.
    """

    _require_internal_token(x_mtls_demo_token)

    return get_server_identity_status()