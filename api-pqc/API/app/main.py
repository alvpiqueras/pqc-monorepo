from fastapi import FastAPI, HTTPException

from app.crypto.kyber import generate_keypair as kyber_generate_keypair
from app.crypto.kyber import encapsulate as kyber_encapsulate
from app.crypto.kyber import decapsulate as kyber_decapsulate

from app.crypto.dilithium import generate_keypair as dilithium_generate_keypair
from app.crypto.dilithium import sign as dilithium_sign
from app.crypto.dilithium import verify as dilithium_verify

from app.models.schemas import (
    KyberEncapsulateRequest,
    KyberDecapsulateRequest,
    DilithiumSignRequest,
    DilithiumVerifyRequest,
)


SERVICE_NAME = "pqc-base"
SERVICE_VERSION = "0.2.0"


app = FastAPI(
    title="PQC Base",
    version=SERVICE_VERSION,
    description=(
        "Base post-quantum cryptography implementation for the migration laboratory. "
        "It exposes core ML-KEM/Kyber and ML-DSA/Dilithium operations used by "
        "higher-level services."
    ),
)


@app.get("/", tags=["General"])
def root():
    return {
        "status": "running",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "docs": "/docs",
        "health": "/health",
        "purpose": "Base PQC primitive layer for the migration laboratory.",
    }


@app.get("/health", tags=["General"])
def health_check():
    return {
        "status": "ok",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
    }


@app.get("/pqc/info", tags=["PQC Theory"])
def pqc_info():
    return {
        "service_name": SERVICE_NAME,
        "layer": "cryptographic-primitives",
        "role_in_laboratory": (
            "This component provides the base post-quantum cryptographic "
            "operations that can be consumed conceptually by the rest of the "
            "infrastructure."
        ),
        "implemented_primitives": {
            "kem": {
                "family": "Kyber / ML-KEM",
                "purpose": "Post-quantum key establishment.",
                "operations": [
                    "key generation",
                    "encapsulation",
                    "decapsulation",
                ],
            },
            "signature": {
                "family": "Dilithium / ML-DSA",
                "purpose": "Post-quantum digital signatures.",
                "operations": [
                    "key generation",
                    "signing",
                    "verification",
                ],
            },
        },
    }


@app.get("/pqc/scenario", tags=["PQC Theory"])
def pqc_scenario():
    return {
        "title": "Base Post-Quantum Cryptography Layer",
        "summary": (
            "This component represents the lowest cryptographic layer of the "
            "PQC migration laboratory. It does not model a complete protocol "
            "by itself. Instead, it exposes the basic primitives that later "
            "layers need in order to build certificates, authenticated services, "
            "secure sessions and verifiable trust models."
        ),
        "why_it_exists": (
            "In a real migration, organizations first need to understand which "
            "cryptographic building blocks replace vulnerable classical schemes. "
            "This component isolates those building blocks before embedding them "
            "into PKI, TLS-like flows, microservices or VPN-like scenarios."
        ),
        "not_a_full_protocol": [
            "It is not a TLS implementation.",
            "It is not a CA or PKI.",
            "It is not a VPN or SSH server.",
            "It only demonstrates primitive-level operations.",
        ],
    }


@app.get("/pqc/primitives", tags=["PQC Theory"])
def pqc_primitives():
    return {
        "ml_kem_kyber": {
            "type": "Key Encapsulation Mechanism",
            "replaces_or_complements": [
                "RSA key transport",
                "ECDH/ECDHE key agreement",
            ],
            "main_goal": (
                "Allow two parties to derive a shared secret over an insecure "
                "channel in a way that is believed to be resistant to quantum "
                "attacks."
            ),
            "typical_use": [
                "TLS key establishment",
                "hybrid handshakes",
                "session key derivation",
                "secure channels between services",
            ],
            "important_note": (
                "A KEM does not usually encrypt application data directly. "
                "It establishes a shared secret, which is then used with a "
                "symmetric cipher such as AES-GCM or ChaCha20-Poly1305."
            ),
        },
        "ml_dsa_dilithium": {
            "type": "Digital Signature Scheme",
            "replaces_or_complements": [
                "RSA signatures",
                "ECDSA signatures",
                "EdDSA signatures",
            ],
            "main_goal": (
                "Provide authenticity and integrity by allowing a verifier to "
                "check that a message or object was signed by the holder of a "
                "private key."
            ),
            "typical_use": [
                "certificate signatures",
                "software signing",
                "signed API requests",
                "identity assertions",
                "registry/log roots",
            ],
        },
    }


@app.get("/pqc/how-to-use", tags=["PQC Theory"])
def pqc_how_to_use():
    return {
        "kem_flow": {
            "primitive": "Kyber / ML-KEM",
            "goal": "Derive a shared secret between two parties.",
            "steps": [
                "The recipient generates an ML-KEM keypair.",
                "The recipient shares its public key.",
                "The sender encapsulates a shared secret using the recipient public key.",
                "The sender obtains a ciphertext and a shared secret.",
                "The ciphertext is sent to the recipient.",
                "The recipient decapsulates the ciphertext using its private key.",
                "Both parties obtain the same shared secret.",
                "That shared secret can then be used to derive a symmetric encryption key.",
            ],
        },
        "signature_flow": {
            "primitive": "Dilithium / ML-DSA",
            "goal": "Prove authenticity and integrity of a message or object.",
            "steps": [
                "The signer generates an ML-DSA keypair.",
                "The signer keeps the private key secret.",
                "The signer shares the public key.",
                "The signer signs a message using the private key.",
                "The verifier checks the signature using the public key.",
                "If verification succeeds, the message is considered authentic and unmodified.",
            ],
        },
        "how_this_component_is_used_later": [
            "A CA-like component can use ML-DSA to sign certificates or identity assertions.",
            "A microservice scenario can use ML-DSA to sign API-to-API requests.",
            "A TLS-like or secure channel scenario can use ML-KEM to establish session secrets.",
            "A registry/log scenario can use signatures to authenticate published roots.",
        ],
    }


@app.post("/kyber/keygen", tags=["ML-KEM / Kyber"])
def kyber_keygen():
    try:
        return kyber_generate_keypair()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/kyber/encapsulate", tags=["ML-KEM / Kyber"])
def kyber_encapsulate_endpoint(request: KyberEncapsulateRequest):
    try:
        return kyber_encapsulate(request.public_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/kyber/decapsulate", tags=["ML-KEM / Kyber"])
def kyber_decapsulate_endpoint(request: KyberDecapsulateRequest):
    try:
        return kyber_decapsulate(request.ciphertext, request.secret_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dilithium/keygen", tags=["ML-DSA / Dilithium"])
def dilithium_keygen():
    try:
        return dilithium_generate_keypair()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dilithium/sign", tags=["ML-DSA / Dilithium"])
def dilithium_sign_endpoint(request: DilithiumSignRequest):
    try:
        return dilithium_sign(request.message, request.secret_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dilithium/verify", tags=["ML-DSA / Dilithium"])
def dilithium_verify_endpoint(request: DilithiumVerifyRequest):
    try:
        return dilithium_verify(
            request.message,
            request.signature,
            request.public_key,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))