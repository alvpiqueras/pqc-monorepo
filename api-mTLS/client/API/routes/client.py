from fastapi import APIRouter, Header, HTTPException

from core.config import settings
from models.client_models import (
    ClientIdentityStatusResponse,
    ConfigureClientIdentityRequest,
    ConfigureClientIdentityResponse,
)
from models.secure_call_models import (
    ClientEncryptedRequestRequest,
    ClientEncryptedRequestResponse,
    ClientHandshakeRequest,
    ClientHandshakeResponse,
)
from services.client_encrypted_request_service import run_client_encrypted_request
from services.client_identity_service import (
    configure_client_identity,
    get_client_identity_status,
)
from services.client_secure_call_service import run_client_handshake


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
    x_mtls_demo_token: str | None = Header(default=None),
):
    _require_internal_token(x_mtls_demo_token)

    identity_status = get_client_identity_status()

    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "service_id": settings.SERVICE_ID,
        "service_role": settings.SERVICE_ROLE,
        "server_service_url": settings.SERVER_SERVICE_URL,
        "status": "running",
        "identity_configured": identity_status["configured"],
        "handshake_ready": identity_status["configured"],
        "encrypted_request_ready": identity_status["configured"],
    }


@router.post(
    "/configure-identity",
    response_model=ConfigureClientIdentityResponse,
    tags=["Identity"],
)
def configure_identity(
    request: ConfigureClientIdentityRequest,
    x_mtls_demo_token: str | None = Header(default=None),
):
    """
    Configure the client service with the certificate material obtained by the gateway.

    This endpoint is intended to be called by the gateway during bootstrap.
    """

    _require_internal_token(x_mtls_demo_token)

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
    x_mtls_demo_token: str | None = Header(default=None),
):
    """
    Return the current in-memory identity configuration status.
    """

    _require_internal_token(x_mtls_demo_token)

    return get_client_identity_status()


@router.post(
    "/secure-call/handshake",
    response_model=ClientHandshakeResponse,
    tags=["Handshake"],
)
async def secure_call_handshake(
    request: ClientHandshakeRequest,
    x_mtls_demo_token: str | None = Header(default=None),
):
    """
    Ask the client service to initiate a handshake with the server service.
    """

    _require_internal_token(x_mtls_demo_token)

    try:
        return await run_client_handshake(request)

    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        )

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


@router.post(
    "/secure-call/encrypted-request",
    response_model=ClientEncryptedRequestResponse,
    tags=["Encrypted Request"],
)
async def secure_call_encrypted_request(
    request: ClientEncryptedRequestRequest,
    x_mtls_demo_token: str | None = Header(default=None),
):
    """
    Ask the client service to send an encrypted request to the server service.

    The client verifies the server certificate, establishes a shared secret with
    ML-KEM and encrypts the application payload with AES-GCM.
    """

    _require_internal_token(x_mtls_demo_token)

    try:
        return await run_client_encrypted_request(request)

    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        )

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