from fastapi import APIRouter

from core.config import settings


router = APIRouter(
    prefix="/intranet",
    tags=["Intranet HTTPS"],
)


@router.get("/info")
def intranet_info():
    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "role": "private-intranet-service-certificate-consumer",
        "expected_server_identity": settings.DEFAULT_EXPECTED_SUBJECT,
        "active_flow": [
            "POST /intranet/artifacts/ca-certificate",
            "POST /intranet/artifacts/server-certificate",
            "POST /intranet/identity/verify",
            "POST /intranet/demo/https-connection",
            "POST /intranet/demo/secure-https-connection",
        ],
        "legacy_note": (
            "Direct PEM-based verification functions remain internally available "
            "in the backend, but are not exposed as public API endpoints."
        ),
    }


@router.get("/scenario")
def intranet_scenario():
    return {
        "title": "Private Intranet HTTPS with PQC X.509 Certificate Validation",
        "summary": (
            "This API simulates an internal corporate client connecting to a "
            "private intranet HTTPS portal. The portal presents an X.509 PQC "
            "server certificate issued by an internal CA, and the client validates "
            "that certificate before trusting the connection."
        ),
        "actors": {
            "internal_client": "Employee browser or corporate device inside the private network.",
            "intranet_server": "Private internal HTTPS portal such as intranet.local.",
            "internal_ca": "Private PQC certificate authority that issued the server certificate.",
        },
        "flow": [
            "The internal client requests access to intranet.local.",
            "The intranet server presents its X.509 PQC certificate.",
            "The client validates the certificate against the registered internal CA artifact.",
            "The client checks that the certificate subject matches the expected intranet identity.",
            "If verification succeeds, a server-authenticated HTTPS session is simulated.",
            "Application data can then be encrypted with AES-GCM in the demo channel.",
        ],
        "cryptographic_scope": {
            "pqc_used_for": "Server certificate and certificate-chain validation.",
            "pqc_not_used_for": (
                "This API does not perform ML-KEM/PQC key exchange. That is left "
                "for more advanced scenarios such as api-mTLS."
            ),
            "symmetric_protection": (
                "AES-256-GCM is used only to simulate protected HTTPS application data."
            ),
        },
        "scope_note": (
            "This is not a production TLS implementation. It is an academic "
            "simulation of the trust and protected-channel logic that appears in "
            "an internal HTTPS flow."
        ),
    }