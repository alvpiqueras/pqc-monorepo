from fastapi import APIRouter, HTTPException

from models.identity_models import (
    HttpsConnectionDemoRequest,
    HttpsConnectionDemoResponse,
    IntranetIdentityVerificationResponse,
    VerifyIntranetIdentityRequest,
)
from services.identity_verification_service import (
    simulate_https_connection,
    verify_intranet_identity,
)


router = APIRouter(
    prefix="/intranet",
    tags=["Intranet Identity"],
)


@router.post(
    "/identity/verify",
    response_model=IntranetIdentityVerificationResponse,
)
def verify_identity(request: VerifyIntranetIdentityRequest):
    """
    Verify the identity of an internal HTTPS portal using registered certificate artifacts.
    """

    try:
        return verify_intranet_identity(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/demo/https-connection",
    response_model=HttpsConnectionDemoResponse,
)
def demo_https_connection(request: HttpsConnectionDemoRequest):
    """
    Simulate a server-authenticated internal HTTPS connection.

    This endpoint intentionally models regular HTTPS, not mTLS.
    """

    try:
        return simulate_https_connection(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))