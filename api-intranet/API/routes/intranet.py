from fastapi import APIRouter
from datetime import datetime, timezone
from core.config import settings

from models.session_models import (
    EncapsulateRequest,
    EncapsulateResponse,
    DecapsulateRequest,
    DecapsulateResponse,
    KemKeypairResponse,
)

from services.pqc_service import (
    get_enabled_algorithms,
    generate_kem_keypair,
    encapsulate_secret,
    decapsulate_secret,
)


router = APIRouter(
    prefix="/intranet",
    tags=["Intranet HTTPS"],
)


@router.get("/info")
def get_intranet_info():
    """
    Return basic information about the simulated internal HTTPS intranet.

    This endpoint describes the role of this API inside the Private Trust
    part of the PQC migration laboratory.
    """

    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "internal_domain": settings.INTERNAL_DOMAIN,
        "internal_ca": settings.INTERNAL_CA_NAME,
        "pqc_enabled": True,
        "kem_algorithm": settings.KEM_ALGORITHM,
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
    }


@router.get("/scenario")
def get_intranet_scenario():
    """
    Explain the purpose of the intranet HTTPS use case.

    This is useful for the future frontend, because the web interface can
    call this endpoint to display a human-readable explanation of the case.
    """

    return {
        "title": "Intranet HTTPS with Post-Quantum Cryptography",
        "summary": (
            "This API simulates an internal HTTPS service deployed inside a "
            "corporate Private Trust environment. The organization controls "
            "its own trust anchors, internal certificate policy and PQC "
            "migration strategy."
        ),
        "classical_baseline": {
            "server_authentication": "X.509 certificate signed with RSA/ECDSA",
            "key_establishment": "ECDHE or classical TLS key exchange",
            "trust_anchor": "Internal corporate CA",
        },
        "pqc_transition": {
            "server_identity": "Certificate-like internal identity signed with ML-DSA",
            "session_secret": "Simulated key establishment using ML-KEM",
            "deployment_model": "Controlled internal rollout",
        },
        "not_implemented_in_this_first_version": [
            "Real PQC-TLS socket integration",
            "Browser-level certificate validation",
            "OCSP/CRL revocation",
            "Full internal PKI hierarchy",
            "mTLS between services",
        ],
    }


@router.get("/algorithms")
def list_enabled_algorithms():
    """
    List the enabled KEM and signature algorithms in the current liboqs build.
    """

    return get_enabled_algorithms()


@router.post("/session/keypair", response_model=KemKeypairResponse)
def create_kem_keypair():
    """
    Generate an ML-KEM keypair for simulating an internal HTTPS session.
    """

    result = generate_kem_keypair()

    return {
        "kem_algorithm": result["kem_algorithm"],
        "public_key_b64": result["public_key_b64"],
        "private_key_b64": result["private_key_b64"],
        "public_key_size_bytes": result["public_key_size_bytes"],
        "private_key_size_bytes": result["private_key_size_bytes"],
        "generated_at": datetime.now(timezone.utc),
    }


@router.post("/session/encapsulate", response_model=EncapsulateResponse)
def create_session_secret(request: EncapsulateRequest):
    """
    Encapsulate a shared secret using the intranet service public key.
    """

    result = encapsulate_secret(request.public_key_b64)

    return {
        "kem_algorithm": result["kem_algorithm"],
        "ciphertext_b64": result["ciphertext_b64"],
        "shared_secret_b64": result["shared_secret_b64"],
        "ciphertext_size_bytes": result["ciphertext_size_bytes"],
        "shared_secret_size_bytes": result["shared_secret_size_bytes"],
        "encapsulated_at": datetime.now(timezone.utc),
    }


@router.post("/session/decapsulate", response_model=DecapsulateResponse)
def recover_session_secret(request: DecapsulateRequest):
    """
    Decapsulate a shared secret using the intranet service private key.
    """

    result = decapsulate_secret(
        private_key_b64=request.private_key_b64,
        ciphertext_b64=request.ciphertext_b64,
    )

    return {
        "kem_algorithm": result["kem_algorithm"],
        "shared_secret_b64": result["shared_secret_b64"],
        "shared_secret_size_bytes": result["shared_secret_size_bytes"],
        "decapsulated_at": datetime.now(timezone.utc),
    }