import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from core.config import settings
from models.certificate_models import (
    CertificateIssueRequest,
    InternalCertificate,
)
from services.pqc_service import (
    generate_signature_keypair,
    sign_message,
    verify_signature,
)


_INTERNAL_CA_KEYPAIR = generate_signature_keypair()


def _now_utc() -> datetime:
    """
    Return the current UTC time using a timezone-aware datetime object.
    """

    return datetime.now(timezone.utc)


def _measure_ms(start_time: float) -> float:
    """
    Return elapsed time in milliseconds.
    """

    return round((time.perf_counter() - start_time) * 1000, 4)


def _canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    """
    Serialize a dictionary into canonical JSON bytes.

    This is important because signatures must be computed over a stable
    representation of the certificate fields.
    """

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _certificate_signed_payload(certificate: InternalCertificate) -> Dict[str, Any]:
    """
    Extract the exact certificate fields that are covered by the issuer signature.

    The signature itself is excluded. This models the classical certificate
    idea where the issuer signs the subject identity, public key, validity
    period and usage constraints.
    """

    return {
        "subject": certificate.subject,
        "service_id": certificate.service_id,
        "issuer": certificate.issuer,
        "trust_model": certificate.trust_model,
        "public_key_algorithm": certificate.public_key_algorithm,
        "public_key_b64": certificate.public_key_b64,
        "issuer_signature_algorithm": certificate.issuer_signature_algorithm,
        "issuer_public_key_b64": certificate.issuer_public_key_b64,
        "usage": certificate.usage,
        "valid_from": certificate.valid_from.isoformat(),
        "valid_to": certificate.valid_to.isoformat(),
    }


def get_internal_ca_info() -> Dict[str, Any]:
    """
    Return public information about the simulated internal CA.

    The private key is deliberately not returned.
    """

    return {
        "issuer": settings.INTERNAL_CA_NAME,
        "trust_model": settings.TRUST_MODEL,
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
        "issuer_public_key_b64": _INTERNAL_CA_KEYPAIR["public_key_b64"],
        "issuer_public_key_size_bytes": _INTERNAL_CA_KEYPAIR["public_key_size_bytes"],
        "generated_at_runtime": True,
        "note": (
            "This internal CA keypair is generated when the API process starts. "
            "It is suitable for an academic demo, but not for production."
        ),
    }


def generate_service_identity(
    service_id: str,
    internal_dns: str,
) -> Dict[str, Any]:
    """
    Generate a post-quantum identity for an internal HTTPS service.

    The generated ML-DSA keypair represents the service identity that will
    later be bound to a certificate-like object.
    """

    keypair = generate_signature_keypair()

    return {
        "service_id": service_id,
        "internal_dns": internal_dns,
        "trust_model": settings.TRUST_MODEL,
        "signature_algorithm": settings.SIGNATURE_ALGORITHM,
        "public_key_b64": keypair["public_key_b64"],
        "private_key_b64": keypair["private_key_b64"],
        "public_key_size_bytes": keypair["public_key_size_bytes"],
        "private_key_size_bytes": keypair["private_key_size_bytes"],
        "generation_time_ms": keypair["generation_time_ms"],
        "generated_at": _now_utc(),
    }


def issue_internal_certificate(
    request: CertificateIssueRequest,
) -> Dict[str, Any]:
    """
    Issue a simplified internal certificate-like object.

    The certificate binds:
    - an internal DNS subject,
    - a service identifier,
    - a post-quantum public key,
    - usage constraints,
    - and validity information.

    The object is then signed by the simulated internal CA using ML-DSA.
    """

    start = time.perf_counter()

    valid_from = _now_utc()
    validity_days = request.validity_days or settings.DEFAULT_CERT_VALIDITY_DAYS
    valid_to = valid_from + timedelta(days=validity_days)

    unsigned_certificate = InternalCertificate(
        subject=request.subject,
        service_id=request.service_id,
        issuer=settings.INTERNAL_CA_NAME,
        trust_model=settings.TRUST_MODEL,
        public_key_algorithm=settings.SIGNATURE_ALGORITHM,
        public_key_b64=request.public_key_b64,
        issuer_signature_algorithm=settings.SIGNATURE_ALGORITHM,
        issuer_public_key_b64=_INTERNAL_CA_KEYPAIR["public_key_b64"],
        usage=_normalize_usage(request.usage),
        valid_from=valid_from,
        valid_to=valid_to,
        signature_b64="",
    )

    signed_payload = _certificate_signed_payload(unsigned_certificate)
    signed_payload_bytes = _canonical_json_bytes(signed_payload)

    signature_result = sign_message(
        message=signed_payload_bytes,
        private_key_b64=_INTERNAL_CA_KEYPAIR["private_key_b64"],
    )

    certificate = unsigned_certificate.model_copy(
        update={"signature_b64": signature_result["signature_b64"]}
    )

    certificate_json_bytes = _canonical_json_bytes(
        certificate.model_dump(mode="json")
    )

    return {
        "certificate": certificate,
        "certificate_size_bytes": len(certificate_json_bytes),
        "signed_payload_size_bytes": len(signed_payload_bytes),
        "signature_size_bytes": signature_result["signature_size_bytes"],
        "issuing_time_ms": _measure_ms(start),
        "issued_at": _now_utc(),
    }


def verify_internal_certificate(
    certificate: InternalCertificate,
) -> Dict[str, Any]:
    """
    Verify a simplified internal certificate-like object.

    Verification checks:
    - the issuer name,
    - the validity window,
    - the expected certificate usage,
    - and the ML-DSA signature over the canonical payload.
    """

    start = time.perf_counter()
    checked_at = _now_utc()

    if certificate.issuer != settings.INTERNAL_CA_NAME:
        return {
            "valid": False,
            "reason": "Certificate issuer does not match the expected internal CA.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "subject": certificate.subject,
            "issuer": certificate.issuer,
            "checked_at": checked_at,
            "verification_time_ms": _measure_ms(start),
        }

    if checked_at < certificate.valid_from:
        return {
            "valid": False,
            "reason": "Certificate is not valid yet.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "subject": certificate.subject,
            "issuer": certificate.issuer,
            "checked_at": checked_at,
            "verification_time_ms": _measure_ms(start),
        }

    if checked_at > certificate.valid_to:
        return {
            "valid": False,
            "reason": "Certificate has expired.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "subject": certificate.subject,
            "issuer": certificate.issuer,
            "checked_at": checked_at,
            "verification_time_ms": _measure_ms(start),
        }

    required_usages = {"server-auth", "internal-https"}
    if not required_usages.issubset(set(certificate.usage)):
        return {
            "valid": False,
            "reason": "Certificate does not contain the required internal HTTPS usages.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "subject": certificate.subject,
            "issuer": certificate.issuer,
            "checked_at": checked_at,
            "verification_time_ms": _measure_ms(start),
        }

    signed_payload = _certificate_signed_payload(certificate)
    signed_payload_bytes = _canonical_json_bytes(signed_payload)

    verification_result = verify_signature(
        message=signed_payload_bytes,
        signature_b64=certificate.signature_b64,
        public_key_b64=certificate.issuer_public_key_b64,
    )

    if not verification_result["valid"]:
        return {
            "valid": False,
            "reason": verification_result["error"] or "Invalid ML-DSA certificate signature.",
            "verified_with": settings.SIGNATURE_ALGORITHM,
            "subject": certificate.subject,
            "issuer": certificate.issuer,
            "checked_at": checked_at,
            "verification_time_ms": _measure_ms(start),
        }

    return {
        "valid": True,
        "reason": "Certificate signature, issuer, validity window and usage constraints are valid.",
        "verified_with": settings.SIGNATURE_ALGORITHM,
        "subject": certificate.subject,
        "issuer": certificate.issuer,
        "checked_at": checked_at,
        "verification_time_ms": _measure_ms(start),
    }

def _normalize_usage(usage: list[str]) -> list[str]:
    """
    Normalize usage strings to the canonical internal certificate format.

    This prevents small input differences such as server_auth vs server-auth
    from breaking the expected usage checks.
    """

    mapping = {
        "server_auth": "server-auth",
        "internal_https": "internal-https",
    }

    return [mapping.get(item, item) for item in usage]