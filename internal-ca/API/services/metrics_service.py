from datetime import datetime, timezone
from typing import Any, Dict

from core.config import settings
from services.certificate_service import get_internal_ca_info
from services.pqc_service import generate_kem_keypair, generate_signature_keypair


def _now_utc() -> datetime:
    """
    Return the current UTC time using a timezone-aware datetime object.
    """

    return datetime.now(timezone.utc)


def get_intranet_metrics() -> Dict[str, Any]:
    """
    Return a compact set of cryptographic metrics for the intranet API.

    These values are generated dynamically and are intended for demonstration
    and comparison purposes inside the PQC migration laboratory.
    """

    kem_keypair = generate_kem_keypair()
    sig_keypair = generate_signature_keypair()
    ca_info = get_internal_ca_info()

    return {
        "service_name": settings.SERVICE_NAME,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "kem_algorithm": settings.KEM_ALGORITHM,
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
        "metrics": {
            "ml_kem": {
                "public_key_size_bytes": kem_keypair["public_key_size_bytes"],
                "private_key_size_bytes": kem_keypair["private_key_size_bytes"],
                "keypair_generation_time_ms": kem_keypair["generation_time_ms"],
            },
            "ml_dsa": {
                "public_key_size_bytes": sig_keypair["public_key_size_bytes"],
                "private_key_size_bytes": sig_keypair["private_key_size_bytes"],
                "keypair_generation_time_ms": sig_keypair["generation_time_ms"],
            },
            "internal_ca": {
                "issuer": ca_info["issuer"],
                "issuer_public_key_size_bytes": ca_info["issuer_public_key_size_bytes"],
                "generated_at_runtime": ca_info["generated_at_runtime"],
            },
        },
        "generated_at": _now_utc(),
    }