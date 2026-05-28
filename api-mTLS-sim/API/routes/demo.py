from fastapi import APIRouter, HTTPException

from models.demo_models import (
    SecureServiceExchangeRequest,
    SecureServiceExchangeResponse,
)
from services.secure_exchange_service import simulate_secure_service_exchange


router = APIRouter(
    prefix="/mtls/demo",
)


@router.get(
    "/secure-service-exchange/info",
    tags=["mTLS Sim - Demo"],
)
def secure_service_exchange_info():
    return {
        "title": "Simulated mTLS Secure Service Exchange",
        "purpose": (
            "Demonstrate a full service-to-service secure exchange after mutual "
            "certificate authentication."
        ),
        "actors": {
            "client_service": (
                "The service initiating the request. It verifies the server "
                "certificate and encrypts the request payload."
            ),
            "server_service": (
                "The service receiving the request. It verifies the client "
                "certificate, decrypts the request and encrypts the response."
            ),
            "internal_ca": (
                "The private trust anchor used by both services to verify peer "
                "certificates."
            ),
        },
        "cryptographic_flow": [
            "The client service verifies the server X.509 PQC certificate.",
            "The server service verifies the client X.509 PQC certificate.",
            "The server service generates an ephemeral ML-KEM keypair.",
            "The client service encapsulates a shared secret using the server public key.",
            "The server service decapsulates the ML-KEM ciphertext.",
            "Both services derive an AES-256-GCM session key using HKDF-SHA256.",
            "The client encrypts the request payload.",
            "The server decrypts the request payload.",
            "The server encrypts the response payload.",
            "The client decrypts the response payload.",
        ],
        "pqc_usage": {
            "certificates": (
                "PQC is used in the X.509 certificates issued by the internal CA."
            ),
            "key_establishment": (
                "ML-KEM/Kyber is used to establish a shared session secret."
            ),
            "symmetric_channel": (
                "AES-256-GCM protects application payloads after session "
                "establishment."
            ),
        },
        "measurements": [
            "mutual_identity_phase_ms",
            "server_kem_keypair_generation_ms",
            "client_kem_encapsulation_ms",
            "server_kem_decapsulation_ms",
            "client_hkdf_key_derivation_ms",
            "server_hkdf_key_derivation_ms",
            "client_request_encryption_ms",
            "server_request_decryption_ms",
            "server_response_encryption_ms",
            "client_response_decryption_ms",
            "total_secure_service_exchange_ms",
        ],
    }


@router.post(
    "/secure-service-exchange",
    response_model=SecureServiceExchangeResponse,
    tags=["mTLS Sim - Demo"],
)
def secure_service_exchange_endpoint(
    request: SecureServiceExchangeRequest,
):
    try:
        return simulate_secure_service_exchange(request)

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))