from fastapi import APIRouter

from core.config import settings


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