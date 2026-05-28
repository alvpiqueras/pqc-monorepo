from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from actors.client_service import (
    decrypt_server_response,
    describe_kem_ciphertext,
    encapsulate_session_secret,
    encrypt_client_request,
)
from actors.server_service import (
    build_server_response,
    decapsulate_session_secret,
    decrypt_client_request,
    describe_server_kem_public_key,
    encrypt_server_response,
    generate_ephemeral_kem_keypair,
)
from models.demo_models import SecureServiceExchangeRequest
from models.handshake_models import MutualIdentityVerificationRequest
from services.mutual_verification_service import verify_mutual_identity


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _fingerprint(data: bytes, length: int = 24) -> str:
    return hashlib.sha256(data).hexdigest()[:length]


def _generate_session_id() -> str:
    return f"mtls_sess_{secrets.token_hex(8)}"


def _derive_aes_key(
    shared_secret: bytes,
    salt: bytes,
    session_id: str,
) -> tuple[bytes, Dict[str, float]]:
    """
    Derive an AES-256-GCM key from the ML-KEM shared secret using HKDF-SHA256.
    """

    start = time.perf_counter()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f"api-mtls-sim|{session_id}|aes-256-gcm".encode("utf-8"),
    )

    key = hkdf.derive(shared_secret)

    end = time.perf_counter()

    measurements = {
        "hkdf_key_derivation_ms": round((end - start) * 1000, 3),
    }

    return key, measurements


def _join_ciphertext_and_tag(
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    return ciphertext + tag


def simulate_secure_service_exchange(
    request: SecureServiceExchangeRequest,
) -> Dict[str, Any]:
    """
    Simulate a full mTLS-like secure service-to-service exchange.

    This endpoint performs:
    - mutual certificate verification;
    - ephemeral ML-KEM session establishment;
    - HKDF key derivation;
    - AES-GCM encrypted client request;
    - AES-GCM encrypted server response.

    It is not a production TLS stack. It is an academic simulation of the
    cryptographic steps that make mTLS different from one-way HTTPS.
    """

    total_start = time.perf_counter()

    # ------------------------------------------------------------
    # 1. Mutual identity verification
    # ------------------------------------------------------------
    mutual_verification_start = time.perf_counter()

    mutual_identity = verify_mutual_identity(
        MutualIdentityVerificationRequest(
            client_service_id=request.client_service_id,
            server_service_id=request.server_service_id,
            ca_artifact_id=request.ca_artifact_id,
            client_certificate_id=request.client_certificate_id,
            server_certificate_id=request.server_certificate_id,
            expected_client_subject=request.expected_client_subject,
            expected_server_subject=request.expected_server_subject,
        )
    )

    mutual_verification_end = time.perf_counter()

    if not mutual_identity["mutual_trust_established"]:
        total_end = time.perf_counter()

        return {
            "exchange_completed": False,
            "reason": (
                "Secure service exchange was not performed because mutual "
                "identity verification failed."
            ),
            "client_service": mutual_identity["client_service"],
            "server_service": mutual_identity["server_service"],
            "mutual_identity_verification": mutual_identity,
            "session": {
                "session_id": None,
                "mode": "mtls-simulated-service-to-service",
                "mutual_authentication": False,
                "kem_algorithm": None,
                "symmetric_cipher": None,
                "ml_kem_established": False,
                "request_encrypted": False,
                "response_encrypted": False,
            },
            "encrypted_request": None,
            "server_processing": None,
            "encrypted_response": None,
            "client_received_response": None,
            "steps": [
                f"Client service '{request.client_service_id}' attempts to connect to server service '{request.server_service_id}'.",
                "The mTLS simulation starts with mutual certificate authentication.",
                "The client service verifies the server certificate.",
                "The server service verifies the client certificate.",
                "At least one side rejected the peer identity.",
                "No ML-KEM session is established.",
                "No AES-GCM protected request or response is exchanged.",
            ],
            "measurements": {
                **mutual_identity["measurements"],
                "mutual_identity_phase_ms": round(
                    (mutual_verification_end - mutual_verification_start) * 1000,
                    3,
                ),
                "total_secure_service_exchange_ms": round(
                    (total_end - total_start) * 1000,
                    3,
                ),
            },
        }

    # ------------------------------------------------------------
    # 2. Server generates ephemeral ML-KEM keypair
    # ------------------------------------------------------------
    session_id = _generate_session_id()

    server_kem, selected_kem_algorithm, server_public_key, server_keygen_metrics = (
        generate_ephemeral_kem_keypair(request.kem_algorithm)
    )

    # ------------------------------------------------------------
    # 3. Client encapsulates session secret to server public key
    # ------------------------------------------------------------
    (
        selected_client_kem_algorithm,
        kem_ciphertext,
        client_shared_secret,
        client_kem_metrics,
    ) = encapsulate_session_secret(
        server_public_key=server_public_key,
        kem_algorithm=selected_kem_algorithm,
    )

    # ------------------------------------------------------------
    # 4. Server decapsulates session secret
    # ------------------------------------------------------------
    server_shared_secret, server_kem_metrics = decapsulate_session_secret(
        kem=server_kem,
        ciphertext=kem_ciphertext,
    )

    shared_secret_match = client_shared_secret == server_shared_secret

    if not shared_secret_match:
        total_end = time.perf_counter()

        return {
            "exchange_completed": False,
            "reason": (
                "ML-KEM session establishment failed because client and server "
                "derived different shared secrets."
            ),
            "client_service": mutual_identity["client_service"],
            "server_service": mutual_identity["server_service"],
            "mutual_identity_verification": mutual_identity,
            "session": {
                "session_id": session_id,
                "mode": "mtls-simulated-service-to-service",
                "mutual_authentication": True,
                "kem_algorithm": selected_kem_algorithm,
                "symmetric_cipher": None,
                "ml_kem_established": False,
                "request_encrypted": False,
                "response_encrypted": False,
            },
            "encrypted_request": None,
            "server_processing": None,
            "encrypted_response": None,
            "client_received_response": None,
            "steps": [
                "Mutual identity verification succeeded.",
                "The server generated an ephemeral ML-KEM keypair.",
                "The client encapsulated a session secret.",
                "The server decapsulated the ML-KEM ciphertext.",
                "The resulting shared secrets did not match.",
                "The protected exchange was aborted.",
            ],
            "measurements": {
                **mutual_identity["measurements"],
                **server_keygen_metrics,
                **client_kem_metrics,
                **server_kem_metrics,
                "total_secure_service_exchange_ms": round(
                    (total_end - total_start) * 1000,
                    3,
                ),
            },
        }

    # ------------------------------------------------------------
    # 5. Derive AES-GCM key from shared secret
    # ------------------------------------------------------------
    salt = secrets.token_bytes(16)

    client_session_key, client_hkdf_metrics = _derive_aes_key(
        shared_secret=client_shared_secret,
        salt=salt,
        session_id=session_id,
    )

    server_session_key, server_hkdf_metrics_raw = _derive_aes_key(
        shared_secret=server_shared_secret,
        salt=salt,
        session_id=session_id,
    )

    server_hkdf_metrics = {
        "server_hkdf_key_derivation_ms": server_hkdf_metrics_raw[
            "hkdf_key_derivation_ms"
        ]
    }

    client_hkdf_metrics = {
        "client_hkdf_key_derivation_ms": client_hkdf_metrics[
            "hkdf_key_derivation_ms"
        ]
    }

    session_key_match = client_session_key == server_session_key

    # ------------------------------------------------------------
    # 6. Client encrypts request
    # ------------------------------------------------------------
    request_aad = (
        f"{session_id}|{request.client_service_id}|{request.server_service_id}|"
        f"{request.action}|{request.resource}|request"
    ).encode("utf-8")

    request_nonce, request_ciphertext, request_tag, request_encryption_metrics = (
        encrypt_client_request(
            session_key=client_session_key,
            plaintext_payload=request.plaintext_payload,
            aad=request_aad,
        )
    )

    request_ciphertext_with_tag = _join_ciphertext_and_tag(
        request_ciphertext,
        request_tag,
    )

    # ------------------------------------------------------------
    # 7. Server decrypts request
    # ------------------------------------------------------------
    decrypted_request_payload, request_decryption_metrics = decrypt_client_request(
        session_key=server_session_key,
        nonce=request_nonce,
        ciphertext_with_tag=request_ciphertext_with_tag,
        aad=request_aad,
    )

    # ------------------------------------------------------------
    # 8. Server processes and encrypts response
    # ------------------------------------------------------------
    server_response_payload = build_server_response(
        client_service_id=request.client_service_id,
        server_service_id=request.server_service_id,
        action=request.action,
        resource=request.resource,
        decrypted_request_payload=decrypted_request_payload,
    )

    server_response_bytes = json.dumps(
        server_response_payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    response_aad = (
        f"{session_id}|{request.server_service_id}|{request.client_service_id}|"
        f"{request.action}|{request.resource}|response"
    ).encode("utf-8")

    response_nonce, response_ciphertext, response_tag, response_encryption_metrics = (
        encrypt_server_response(
            session_key=server_session_key,
            response_payload=server_response_bytes,
            aad=response_aad,
        )
    )

    response_ciphertext_with_tag = _join_ciphertext_and_tag(
        response_ciphertext,
        response_tag,
    )

    # ------------------------------------------------------------
    # 9. Client decrypts response
    # ------------------------------------------------------------
    decrypted_response_payload, response_decryption_metrics = decrypt_server_response(
        session_key=client_session_key,
        nonce=response_nonce,
        ciphertext_with_tag=response_ciphertext_with_tag,
        aad=response_aad,
    )

    total_end = time.perf_counter()

    steps = [
        f"Client service '{request.client_service_id}' initiates a connection to server service '{request.server_service_id}'.",
        "The server service presents its X.509 PQC certificate.",
        "The client service verifies the server certificate against the internal CA.",
        "The client service presents its X.509 PQC certificate.",
        "The server service verifies the client certificate against the internal CA.",
        "Mutual identity verification succeeds.",
        "The server service generates an ephemeral ML-KEM keypair for this simulated session.",
        "The client service encapsulates a shared secret using the server ML-KEM public key.",
        "The server service decapsulates the ML-KEM ciphertext and obtains the same shared secret.",
        "Both services derive an AES-256-GCM session key from the shared secret using HKDF-SHA256.",
        "The client service encrypts the application request with AES-256-GCM.",
        "The server service decrypts the request inside the protected channel.",
        "The server service processes the request and encrypts the response.",
        "The client service decrypts the response.",
        "The simulated mTLS secure service exchange is completed.",
    ]

    measurements: Dict[str, float] = {
        **mutual_identity["measurements"],
        "mutual_identity_phase_ms": round(
            (mutual_verification_end - mutual_verification_start) * 1000,
            3,
        ),
        **server_keygen_metrics,
        **client_kem_metrics,
        **server_kem_metrics,
        **client_hkdf_metrics,
        **server_hkdf_metrics,
        **request_encryption_metrics,
        **request_decryption_metrics,
        **response_encryption_metrics,
        **response_decryption_metrics,
        "total_secure_service_exchange_ms": round(
            (total_end - total_start) * 1000,
            3,
        ),
    }

    return {
        "exchange_completed": True,
        "reason": (
            "Secure service-to-service exchange completed after successful "
            "mutual authentication, ML-KEM session establishment and AES-GCM "
            "payload protection."
        ),
        "client_service": {
            **mutual_identity["client_service"],
            "verified_server_identity": True,
            "derived_session_key": True,
        },
        "server_service": {
            **mutual_identity["server_service"],
            "verified_client_identity": True,
            "derived_session_key": True,
        },
        "mutual_identity_verification": mutual_identity,
        "session": {
            "session_id": session_id,
            "mode": "mtls-simulated-service-to-service",
            "mutual_authentication": True,
            "client_authenticated": True,
            "server_authenticated": True,
            "kem_algorithm_requested": request.kem_algorithm,
            "kem_algorithm_used": selected_kem_algorithm,
            "client_kem_algorithm_used": selected_client_kem_algorithm,
            "ml_kem_established": True,
            "shared_secret_match": shared_secret_match,
            "shared_secret_fingerprint": _fingerprint(client_shared_secret),
            "hkdf_salt_b64": _b64(salt),
            "session_key_match": session_key_match,
            "session_key_fingerprint": _fingerprint(client_session_key),
            "symmetric_cipher": "AES-256-GCM",
            "key_exchange_note": (
                "ML-KEM is used to establish a shared secret. HKDF-SHA256 derives "
                "the AES-GCM session key from that shared secret."
            ),
        },
        "encrypted_request": {
            "aad_b64": _b64(request_aad),
            "nonce_b64": _b64(request_nonce),
            "ciphertext_b64": _b64(request_ciphertext),
            "tag_b64": _b64(request_tag),
            "plaintext_size_bytes": len(request.plaintext_payload.encode("utf-8")),
            "ciphertext_size_bytes": len(request_ciphertext),
            "tag_size_bytes": len(request_tag),
            "nonce_size_bytes": len(request_nonce),
            "kem": {
                **describe_server_kem_public_key(server_public_key),
                **describe_kem_ciphertext(kem_ciphertext),
                "kem_ciphertext_b64": _b64(kem_ciphertext),
                "kem_ciphertext_size_bytes": len(kem_ciphertext),
            },
        },
        "server_processing": {
            "request_decryption_success": True,
            "decrypted_request_payload": decrypted_request_payload,
            "action": request.action,
            "resource": request.resource,
            "response_plaintext_size_bytes": len(server_response_bytes),
        },
        "encrypted_response": {
            "aad_b64": _b64(response_aad),
            "nonce_b64": _b64(response_nonce),
            "ciphertext_b64": _b64(response_ciphertext),
            "tag_b64": _b64(response_tag),
            "plaintext_size_bytes": len(server_response_bytes),
            "ciphertext_size_bytes": len(response_ciphertext),
            "tag_size_bytes": len(response_tag),
            "nonce_size_bytes": len(response_nonce),
        },
        "client_received_response": {
            "response_decryption_success": True,
            "decrypted_response_payload": json.loads(decrypted_response_payload),
        },
        "steps": steps,
        "measurements": measurements,
    }