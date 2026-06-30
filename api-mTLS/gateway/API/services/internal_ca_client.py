from __future__ import annotations

import time
from typing import Any, Dict

import httpx

from core.config import settings


def _internal_ca_url() -> str:
    return settings.INTERNAL_CA_URL.rstrip("/")


async def generate_ca(
    common_name: str,
    signature_algorithm: str,
    validity_days: int,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    """
    Call internal-ca to generate a PQC internal CA.
    """

    start = time.perf_counter()

    payload = {
        "common_name": common_name,
        "signature_algorithm": signature_algorithm,
        "validity_days": validity_days,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{_internal_ca_url()}/ca/generate",
            json=payload,
        )

    end = time.perf_counter()

    response.raise_for_status()

    return response.json(), {
        "ca_generation_http_ms": round((end - start) * 1000, 3),
    }


async def generate_csr(
    common_name: str,
    signature_algorithm: str,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    """
    Call internal-ca to generate a PQC keypair and CSR for a service.
    """

    start = time.perf_counter()

    payload = {
        "common_name": common_name,
        "signature_algorithm": signature_algorithm,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{_internal_ca_url()}/ca/csr/generate",
            json=payload,
        )

    end = time.perf_counter()

    response.raise_for_status()

    return response.json(), {
        "csr_generation_http_ms": round((end - start) * 1000, 3),
    }


async def issue_certificate(
    ca_id: str,
    csr_id: str,
    validity_days: int,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    """
    Call internal-ca to issue a certificate from a previously generated CSR.
    """

    start = time.perf_counter()

    payload = {
        "ca_id": ca_id,
        "csr_id": csr_id,
        "validity_days": validity_days,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{_internal_ca_url()}/ca/certificate/issue",
            json=payload,
        )

    end = time.perf_counter()

    response.raise_for_status()

    return response.json(), {
        "certificate_issuance_http_ms": round((end - start) * 1000, 3),
    }


def extract_required_field(
    payload: Dict[str, Any],
    field_name: str,
    context: str,
) -> Any:
    """
    Extract a required field from an internal-ca response.

    Raises a clear error if the internal-ca response shape changes.
    """

    value = payload.get(field_name)

    if value is None:
        raise ValueError(
            f"Missing field '{field_name}' in internal-ca response for {context}."
        )

    return value