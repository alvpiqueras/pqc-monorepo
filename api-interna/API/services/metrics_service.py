import statistics
import time
from datetime import datetime, timezone
from typing import Any, Dict

from core.config import settings
from services.pqc_service import generate_signature_keypair, sign_message, verify_signature


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_demo_message() -> bytes:
    return b"internal-api-latency-demo-message"


def get_internal_api_metrics(iterations: int = 5) -> Dict[str, Any]:
    """
    Measure repeated ML-DSA sign/verify operations for API-to-API requests.

    Unlike api-intranet, this endpoint focuses on repeated operation latency,
    not on static key and signature sizes.
    """

    iterations = max(1, min(iterations, 20))

    keypair = generate_signature_keypair()
    message = _canonical_demo_message()

    sign_times = []
    verify_times = []

    for _ in range(iterations):
        sign_result = sign_message(
            message=message,
            private_key_b64=keypair["private_key_b64"],
        )
        sign_times.append(sign_result["signing_time_ms"])

        verify_result = verify_signature(
            message=message,
            signature_b64=sign_result["signature_b64"],
            public_key_b64=keypair["public_key_b64"],
        )
        verify_times.append(verify_result["verification_time_ms"])

    return {
        "service_name": settings.SERVICE_NAME,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
        "iterations": iterations,
        "latency_metrics_ms": {
            "sign": {
                "min": min(sign_times),
                "max": max(sign_times),
                "mean": round(statistics.mean(sign_times), 4),
            },
            "verify": {
                "min": min(verify_times),
                "max": max(verify_times),
                "mean": round(statistics.mean(verify_times), 4),
            },
        },
        "generated_at": _now_utc(),
    }