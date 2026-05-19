import base64
import time
from typing import Any, Dict

import oqs

from core.config import settings


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _b64decode(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("utf-8"))


def _measure_ms(start_time: float) -> float:
    return round((time.perf_counter() - start_time) * 1000, 4)


def get_enabled_algorithms() -> Dict[str, Any]:
    get_kems = getattr(oqs, "get_enabled_KEM_mechanisms", None)
    get_sigs = getattr(oqs, "get_enabled_sig_mechanisms", None)

    return {
        "kem_algorithms": get_kems() if callable(get_kems) else [],
        "signature_algorithms": get_sigs() if callable(get_sigs) else [],
        "default_kem_algorithm": settings.KEM_ALGORITHM,
        "default_signature_algorithm": settings.SIGNATURE_ALGORITHM,
    }


def generate_signature_keypair() -> Dict[str, Any]:
    start = time.perf_counter()

    with oqs.Signature(settings.SIGNATURE_ALGORITHM) as signer: # type: ignore[attr-defined]
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

    return {
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
        "public_key_b64": _b64encode(public_key),
        "private_key_b64": _b64encode(private_key),
        "generation_time_ms": _measure_ms(start),
    }


def sign_message(message: bytes, private_key_b64: str) -> Dict[str, Any]:
    private_key = _b64decode(private_key_b64)

    start = time.perf_counter()

    with oqs.Signature(                    # type: ignore[attr-defined]
        settings.SIGNATURE_ALGORITHM,
        secret_key=private_key,
    ) as signer:
        signature = signer.sign(message)

    return {
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
        "signature_b64": _b64encode(signature),
        "signature_size_bytes": len(signature),
        "signing_time_ms": _measure_ms(start),
    }


def verify_signature(
    message: bytes,
    signature_b64: str,
    public_key_b64: str,
) -> Dict[str, Any]:
    public_key = _b64decode(public_key_b64)
    signature = _b64decode(signature_b64)

    start = time.perf_counter()

    try:
        with oqs.Signature(settings.SIGNATURE_ALGORITHM) as verifier:  # type: ignore[attr-defined]
            is_valid = verifier.verify(message, signature, public_key)

        return {
            "valid": bool(is_valid),
            "signature_algorithm": settings.SIGNATURE_ALGORITHM,
            "verification_time_ms": _measure_ms(start),
            "error": None,
        }

    except Exception as exc:
        return {
            "valid": False,
            "signature_algorithm": settings.SIGNATURE_ALGORITHM,
            "verification_time_ms": _measure_ms(start),
            "error": str(exc),
        }


def generate_kem_keypair() -> Dict[str, Any]:
    start = time.perf_counter()

    with oqs.KeyEncapsulation(settings.KEM_ALGORITHM) as kem:     # type: ignore[attr-defined]
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

    return {
        "kem_algorithm": settings.KEM_ALGORITHM,
        "public_key_b64": _b64encode(public_key),
        "private_key_b64": _b64encode(private_key),
        "generation_time_ms": _measure_ms(start),
    }


def encapsulate_secret(public_key_b64: str) -> Dict[str, Any]:
    public_key = _b64decode(public_key_b64)

    start = time.perf_counter()

    with oqs.KeyEncapsulation(settings.KEM_ALGORITHM) as kem:            # type: ignore[attr-defined]
        ciphertext, shared_secret = kem.encap_secret(public_key)

    return {
        "kem_algorithm": settings.KEM_ALGORITHM,
        "ciphertext_b64": _b64encode(ciphertext),
        "shared_secret_b64": _b64encode(shared_secret),
        "encapsulation_time_ms": _measure_ms(start),
    }


def decapsulate_secret(
    private_key_b64: str,
    ciphertext_b64: str,
) -> Dict[str, Any]:
    private_key = _b64decode(private_key_b64)
    ciphertext = _b64decode(ciphertext_b64)

    start = time.perf_counter()

    with oqs.KeyEncapsulation(               # type: ignore[attr-defined]
        settings.KEM_ALGORITHM,
        secret_key=private_key,
    ) as kem:
        shared_secret = kem.decap_secret(ciphertext)

    return {
        "kem_algorithm": settings.KEM_ALGORITHM,
        "shared_secret_b64": _b64encode(shared_secret),
        "decapsulation_time_ms": _measure_ms(start),
    }