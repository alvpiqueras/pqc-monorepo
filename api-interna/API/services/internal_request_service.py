import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from core.config import settings
from models.request_models import (
    InternalApiRequestPayload,
    SignInternalRequestInput,
    SignedInternalApiRequest,
)
from services.pqc_service import generate_signature_keypair, sign_message, verify_signature


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _measure_ms(start_time: float) -> float:
    return round((time.perf_counter() - start_time) * 1000, 4)


def _canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _payload_to_signed_bytes(payload: InternalApiRequestPayload) -> bytes:
    return _canonical_json_bytes(payload.model_dump(mode="json"))


def generate_service_identity(
    service_id: str,
    service_role: str,
) -> Dict[str, Any]:
    keypair = generate_signature_keypair()

    return {
        "service_id": service_id,
        "service_role": service_role,
        "internal_domain": settings.INTERNAL_DOMAIN,
        "trust_model": settings.TRUST_MODEL,
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
        "public_key_b64": keypair["public_key_b64"],
        "private_key_b64": keypair["private_key_b64"],
        "generation_time_ms": keypair["generation_time_ms"],
        "generated_at": _now_utc(),
    }


def sign_internal_request(
    request: SignInternalRequestInput,
) -> Dict[str, Any]:
    start = time.perf_counter()

    issued_at = _now_utc()
    validity_seconds = (
        request.validity_seconds
        or settings.DEFAULT_REQUEST_VALIDITY_SECONDS
    )
    expires_at = issued_at + timedelta(seconds=validity_seconds)

    payload = InternalApiRequestPayload(
        request_id=str(uuid.uuid4()),
        service_id=request.service_id,
        service_role=request.service_role,
        target_api=request.target_api,
        action=request.action,
        resource=request.resource,
        issued_at=issued_at,
        expires_at=expires_at,
        claims=request.claims,
    )

    signed_payload_bytes = _payload_to_signed_bytes(payload)

    signature_result = sign_message(
        message=signed_payload_bytes,
        private_key_b64=request.private_key_b64,
    )

    return {
        "payload": payload,
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
        "signature_b64": signature_result["signature_b64"],
        "signed_payload_size_bytes": len(signed_payload_bytes),
        "signature_size_bytes": signature_result["signature_size_bytes"],
        "signing_time_ms": _measure_ms(start),
    }


def verify_internal_request(
    signed_request: SignedInternalApiRequest,
    service_public_key_b64: str,
    expected_target_api: str,
    allowed_actions: list[str],
) -> Dict[str, Any]:
    start = time.perf_counter()
    checked_at = _now_utc()
    payload = signed_request.payload

    signed_payload_bytes = _payload_to_signed_bytes(payload)

    verification_result = verify_signature(
        message=signed_payload_bytes,
        signature_b64=signed_request.signature_b64,
        public_key_b64=service_public_key_b64,
    )

    if not verification_result["valid"]:
        return {
            "valid": False,
            "reason": verification_result["error"] or "Invalid ML-DSA request signature.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "service_id": payload.service_id,
            "target_api": payload.target_api,
            "action": payload.action,
            "verification_time_ms": _measure_ms(start),
            "checked_at": checked_at,
        }

    if checked_at > payload.expires_at:
        return {
            "valid": False,
            "reason": "Signed internal API request has expired.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "service_id": payload.service_id,
            "target_api": payload.target_api,
            "action": payload.action,
            "verification_time_ms": _measure_ms(start),
            "checked_at": checked_at,
        }

    if payload.target_api != expected_target_api:
        return {
            "valid": False,
            "reason": "Signed request targets a different internal API.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "service_id": payload.service_id,
            "target_api": payload.target_api,
            "action": payload.action,
            "verification_time_ms": _measure_ms(start),
            "checked_at": checked_at,
        }

    if payload.action not in allowed_actions:
        return {
            "valid": False,
            "reason": "Requested action is not allowed for this internal API.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "service_id": payload.service_id,
            "target_api": payload.target_api,
            "action": payload.action,
            "verification_time_ms": _measure_ms(start),
            "checked_at": checked_at,
        }

    return {
        "valid": True,
        "reason": "Signed internal API request is valid.",
        "verified_with": settings.SIGNATURE_ALGORITHM,
        "service_id": payload.service_id,
        "target_api": payload.target_api,
        "action": payload.action,
        "verification_time_ms": _measure_ms(start),
        "checked_at": checked_at,
    }