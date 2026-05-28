from fastapi import APIRouter, HTTPException

from models.handshake_models import (
    MutualIdentityVerificationRequest,
    MutualIdentityVerificationResponse,
)
from services.mutual_verification_service import verify_mutual_identity


router = APIRouter(
    prefix="/mtls/handshake",
)


@router.get(
    "/verify-mutual-identity/info",
    tags=["Handshake"],
)
def verify_mutual_identity_info():
    return {
        "title": "mTLS Mutual Identity Verification",
        "purpose": (
            "Verify both sides of a simulated mTLS service-to-service connection. "
            "The client service validates the server certificate, and the server "
            "service validates the client certificate."
        ),
        "scope": {
            "models": "mutual certificate authentication in a Private Trust environment",
            "does_not_model": [
                "a production TLS stack",
                "a real network-level TLS handshake",
                "browser-based TLS",
                "certificate revocation checking",
            ],
        },
        "actors": {
            "client_service": (
                "The service initiating the connection. It verifies the server "
                "certificate before trusting the target service."
            ),
            "server_service": (
                "The service receiving the connection. It verifies the client "
                "certificate before accepting the caller identity."
            ),
            "internal_ca": (
                "The private trust anchor used to verify both certificates."
            ),
        },
        "required_artifacts": [
            "ca_artifact_id",
            "client_certificate_id",
            "server_certificate_id",
        ],
        "trust_decision": (
            "Mutual trust is established only if both certificate-chain checks "
            "succeed and both certificate subjects match the expected identities."
        ),
        "measurements": [
            "artifact_loading_ms",
            "client_side_server_verification_ms",
            "server_side_client_verification_ms",
            "total_mutual_identity_verification_ms",
        ],
        "next_phase": (
            "Phase C will reuse this mutual identity verification step before "
            "simulating a protected service-to-service exchange with ML-KEM and "
            "AES-GCM."
        ),
    }


@router.post(
    "/verify-mutual-identity",
    response_model=MutualIdentityVerificationResponse,
    tags=["Handshake"],
)
def verify_mutual_identity_endpoint(
    request: MutualIdentityVerificationRequest,
):
    try:
        return verify_mutual_identity(request)

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))