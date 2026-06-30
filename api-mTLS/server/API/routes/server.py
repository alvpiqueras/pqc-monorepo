from fastapi import APIRouter, Header, HTTPException

from core.config import settings
from models.handshake_models import (
    ServerHandshakeStartRequest,
    ServerHandshakeStartResponse,
)
from models.server_models import (
    ConfigureServerIdentityRequest,
    ConfigureServerIdentityResponse,
    ServerIdentityStatusResponse,
)
from services.server_handshake_service import start_server_handshake
from services.server_identity_service import (
    configure_server_identity,
    get_server_identity_status,
)

from models.secure_endpoint_models import (
    EncryptedRequestFromClient,
    SecureEndpointResponse,
)
from services.server_secure_endpoint_service import process_encrypted_request

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

    identity_status = get_server_identity_status()

    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "service_id": settings.SERVICE_ID,
        "service_role": settings.SERVICE_ROLE,
        "status": "running",
        "identity_configured": identity_status["configured"],
        "phase_c1_ready": identity_status["configured"],
        "default_kem_algorithm": settings.DEFAULT_KEM_ALGORITHM,
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


@router.post(
    "/handshake/start",
    response_model=ServerHandshakeStartResponse,
    tags=["Handshake"],
)
def handshake_start(
    request: ServerHandshakeStartRequest,
    x_mtls_demo_token: str | None = Header(default=None),
):
    """
    Phase C1 endpoint.

    The client calls this endpoint to ask the server to start an application-level
    mTLS-like handshake. The server returns its certificate and an ephemeral
    ML-KEM public key.
    """

    _require_internal_token(x_mtls_demo_token)

    try:
        return start_server_handshake(request)

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
    "/secure-endpoint",
    response_model=SecureEndpointResponse,
    tags=["Secure Endpoint"],
)
def secure_endpoint(
    request: EncryptedRequestFromClient,
    x_mtls_demo_token: str | None = Header(default=None),
):
    """
    Receive and process an encrypted service-to-service request.

    The server verifies the client certificate, decapsulates the ML-KEM shared
    secret and decrypts the AES-GCM protected payload.
    """

    _require_internal_token(x_mtls_demo_token)

    try:
        return process_encrypted_request(request)

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