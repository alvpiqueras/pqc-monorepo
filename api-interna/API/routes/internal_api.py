from datetime import datetime, timezone

from fastapi import APIRouter, Query

from core.config import settings
from models.request_models import (
    SignInternalRequestInput,
    SignedInternalApiRequest,
    VerifyInternalRequestInput,
    VerifyInternalRequestResponse,
)
from models.service_models import (
    ServiceIdentityRequest,
    ServiceIdentityResponse,
)
from models.session_models import (
    DecapsulateRequest,
    DecapsulateResponse,
    EncapsulateRequest,
    EncapsulateResponse,
    KemKeypairResponse,
)
from services.internal_request_service import (
    generate_service_identity,
    sign_internal_request,
    verify_internal_request,
)
from services.metrics_service import get_internal_api_metrics
from services.pqc_service import (
    decapsulate_secret,
    encapsulate_secret,
    generate_kem_keypair,
    get_enabled_algorithms,
)


router = APIRouter(
    prefix="/internal-api",
    tags=["Internal APIs"],
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/info")
def get_internal_api_info():
    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "internal_domain": settings.INTERNAL_DOMAIN,
        "pqc_enabled": True,
        "kem_algorithm": settings.KEM_ALGORITHM,
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
    }


@router.get("/scenario")
def get_internal_api_scenario():
    return {
        "title": "Internal APIs and Microservices with Post-Quantum Cryptography",
        "summary": (
            "This API simulates internal service-to-service communication "
            "inside a corporate microservices environment using "
            "post-quantum cryptographic primitives."
        ),
        "classical_baseline": {
            "authentication": "JWT, API keys or classical signatures",
            "trust_model": "private-trust",
            "service_identity": "internal certificates or tokens",
        },
        "pqc_transition": {
            "service_identity": "ML-DSA signatures",
            "shared_secret_establishment": "ML-KEM",
            "deployment_scope": "internal APIs and microservices",
        },
        "academic_scope": {
            "implemented": [
                "PQC service identities",
                "Signed internal API requests",
                "Verification of internal requests",
                "ML-KEM shared secret establishment",
                "Repeated sign/verify latency metrics",
            ],
            "not_implemented": [
                "Real JWT infrastructure",
                "OAuth2",
                "mTLS",
                "Service mesh integration",
                "Kubernetes integration",
            ],
        },
    }


@router.get("/algorithms")
def list_enabled_algorithms():
    return get_enabled_algorithms()


@router.post("/service/generate", response_model=ServiceIdentityResponse)
def create_service_identity(request: ServiceIdentityRequest):
    return generate_service_identity(
        service_id=request.service_id,
        service_role=request.service_role,
    )


@router.post("/request/sign", response_model=SignedInternalApiRequest)
def create_signed_internal_request(request: SignInternalRequestInput):
    return sign_internal_request(request)


@router.post("/request/verify", response_model=VerifyInternalRequestResponse)
def verify_signed_internal_request(request: VerifyInternalRequestInput):
    return verify_internal_request(
        signed_request=request.signed_request,
        service_public_key_b64=request.service_public_key_b64,
        expected_target_api=request.expected_target_api,
        allowed_actions=request.allowed_actions,
    )


@router.post("/session/keypair", response_model=KemKeypairResponse)
def create_kem_keypair():
    result = generate_kem_keypair()

    return {
        "kem_algorithm": result["kem_algorithm"],
        "public_key_b64": result["public_key_b64"],
        "private_key_b64": result["private_key_b64"],
        "generated_at": _now_utc(),
    }


@router.post("/session/encapsulate", response_model=EncapsulateResponse)
def create_session_secret(request: EncapsulateRequest):
    result = encapsulate_secret(request.public_key_b64)

    return {
        "kem_algorithm": result["kem_algorithm"],
        "ciphertext_b64": result["ciphertext_b64"],
        "shared_secret_b64": result["shared_secret_b64"],
        "encapsulation_time_ms": result["encapsulation_time_ms"],
        "encapsulated_at": _now_utc(),
    }


@router.post("/session/decapsulate", response_model=DecapsulateResponse)
def recover_session_secret(request: DecapsulateRequest):
    result = decapsulate_secret(
        private_key_b64=request.private_key_b64,
        ciphertext_b64=request.ciphertext_b64,
    )

    return {
        "kem_algorithm": result["kem_algorithm"],
        "shared_secret_b64": result["shared_secret_b64"],
        "decapsulation_time_ms": result["decapsulation_time_ms"],
        "decapsulated_at": _now_utc(),
    }


@router.get("/metrics")
def get_metrics(
    iterations: int = Query(
        default=5,
        ge=1,
        le=20,
        description="Number of repeated sign/verify operations.",
    )
):
    return get_internal_api_metrics(iterations=iterations)