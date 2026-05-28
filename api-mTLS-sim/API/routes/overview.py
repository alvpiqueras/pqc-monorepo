from fastapi import APIRouter

from core.config import settings


router = APIRouter(
    prefix="/mtls",
)


@router.get(
    "/info",
    tags=["mTLS Sim - Overview"],
)
def mtls_info():
    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "component_role": settings.COMPONENT_ROLE,
        "default_client_service_id": settings.DEFAULT_CLIENT_SERVICE_ID,
        "default_server_service_id": settings.DEFAULT_SERVER_SERVICE_ID,
        "default_client_subject": settings.DEFAULT_CLIENT_SUBJECT,
        "default_server_subject": settings.DEFAULT_SERVER_SUBJECT,
    }


@router.get(
    "/scenario",
    tags=["mTLS Sim - Overview"],
)
def mtls_scenario():
    return {
        "title": "Simulated Mutual TLS with PQC X.509 Certificates",
        "summary": (
            "This API simulates mutual TLS-style authentication between two "
            "internal services in a Private Trust environment. Both services "
            "use X.509 PQC certificates issued by an internal CA."
        ),
        "actors": {
            "client_service": (
                "The service initiating the connection. Example: billing-service."
            ),
            "server_service": (
                "The service receiving the connection. Example: customer-api."
            ),
            "internal_ca": (
                "Private PQC certificate authority trusted by both services."
            ),
        },
        "intended_flow": [
            "The client service initiates a connection to the server service.",
            "The server presents its X.509 PQC certificate.",
            "The client verifies the server certificate against the internal CA.",
            "The client presents its own X.509 PQC certificate.",
            "The server verifies the client certificate against the internal CA.",
            "If both verifications succeed, mutual trust is established.",
            "A secure service-to-service exchange can then be simulated.",
        ],
        "cryptographic_scope": {
            "pqc_used_for": (
                "PQC is used in the X.509 certificates consumed by the simulation."
            ),
            "phase_a_scope": (
                "Phase A only registers certificate artifacts. Mutual verification "
                "and secure exchange are implemented in later phases."
            ),
            "not_a_real_tls_stack": (
                "This API does not terminate real TLS connections. It is an academic "
                "simulation of the logical trust decisions and cryptographic steps "
                "inside an mTLS-like service-to-service flow."
            ),
        },
    }