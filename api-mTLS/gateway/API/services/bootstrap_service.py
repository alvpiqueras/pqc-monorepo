from __future__ import annotations

import time
from typing import Any, Dict

import httpx

from core.config import settings
from models.bootstrap_models import BootstrapFromInternalCaRequest
from services.internal_ca_client import (
    extract_required_field,
    generate_ca,
    generate_csr,
    issue_certificate,
)


LATEST_BOOTSTRAP_STATE: Dict[str, Any] = {
    "bootstrap_completed": False,
    "latest_bootstrap": None,
}


def _internal_headers() -> dict[str, str]:
    return {
        "X-QCS-Demo-Token": settings.INTERNAL_DEMO_TOKEN,
    }


async def _configure_client_service(
    ca_certificate_pem: str,
    client_certificate_pem: str,
    expected_server_subject: str,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    """
    Configure the real client service with its certificate identity.
    """

    start = time.perf_counter()

    payload = {
        "service_id": "billing-service",
        "ca_certificate_pem": ca_certificate_pem,
        "own_certificate_pem": client_certificate_pem,
        "expected_server_subject": expected_server_subject,
        "server_service_url": settings.SERVER_SERVICE_URL,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{settings.CLIENT_SERVICE_URL.rstrip('/')}/client/configure-identity",
            json=payload,
            headers=_internal_headers(),
        )

    end = time.perf_counter()

    response.raise_for_status()

    return response.json(), {
        "client_configuration_http_ms": round((end - start) * 1000, 3),
    }


async def _configure_server_service(
    ca_certificate_pem: str,
    server_certificate_pem: str,
    expected_client_subject: str,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    """
    Configure the real server service with its certificate identity.
    """

    start = time.perf_counter()

    payload = {
        "service_id": "customer-api",
        "ca_certificate_pem": ca_certificate_pem,
        "own_certificate_pem": server_certificate_pem,
        "expected_client_subject": expected_client_subject,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{settings.SERVER_SERVICE_URL.rstrip('/')}/server/configure-identity",
            json=payload,
            headers=_internal_headers(),
        )

    end = time.perf_counter()

    response.raise_for_status()

    return response.json(), {
        "server_configuration_http_ms": round((end - start) * 1000, 3),
    }


async def _get_client_identity_status() -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{settings.CLIENT_SERVICE_URL.rstrip('/')}/client/identity/status",
            headers=_internal_headers(),
        )

    response.raise_for_status()
    return response.json()


async def _get_server_identity_status() -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{settings.SERVER_SERVICE_URL.rstrip('/')}/server/identity/status",
            headers=_internal_headers(),
        )

    response.raise_for_status()
    return response.json()


async def bootstrap_from_internal_ca(
    request: BootstrapFromInternalCaRequest,
) -> Dict[str, Any]:
    """
    Bootstrap the distributed mTLS demo using the real internal-ca API.

    This function:
    - generates a CA;
    - generates CSRs for client and server;
    - issues client/server certificates;
    - configures the real client and server services.
    """

    total_start = time.perf_counter()

    steps: list[str] = []
    measurements: Dict[str, float] = {}

    steps.append("Gateway contacts internal-ca to generate a PQC internal CA.")

    ca_response, ca_metrics = await generate_ca(
        common_name=request.ca_common_name,
        signature_algorithm=request.signature_algorithm,
        validity_days=request.validity_days,
    )
    measurements.update(ca_metrics)

    ca_id = extract_required_field(ca_response, "ca_id", "CA generation")
    ca_certificate_pem = extract_required_field(
        ca_response,
        "certificate_pem",
        "CA generation",
    )

    steps.append("Internal CA generated successfully.")

    steps.append("Gateway requests a CSR for the client service.")

    client_csr_response, client_csr_metrics = await generate_csr(
        common_name=request.client_common_name,
        signature_algorithm=request.signature_algorithm,
    )
    measurements["client_csr_generation_http_ms"] = client_csr_metrics[
        "csr_generation_http_ms"
    ]

    client_csr_id = extract_required_field(
        client_csr_response,
        "csr_id",
        "client CSR generation",
    )

    steps.append("Client service CSR generated successfully.")

    steps.append("Gateway requests a certificate for the client service.")

    client_cert_response, client_cert_metrics = await issue_certificate(
        ca_id=ca_id,
        csr_id=client_csr_id,
        validity_days=request.validity_days,
    )
    measurements["client_certificate_issuance_http_ms"] = client_cert_metrics[
        "certificate_issuance_http_ms"
    ]

    client_certificate_id = extract_required_field(
        client_cert_response,
        "certificate_id",
        "client certificate issuance",
    )
    client_certificate_pem = extract_required_field(
        client_cert_response,
        "certificate_pem",
        "client certificate issuance",
    )

    steps.append("Client service certificate issued successfully.")

    steps.append("Gateway requests a CSR for the server service.")

    server_csr_response, server_csr_metrics = await generate_csr(
        common_name=request.server_common_name,
        signature_algorithm=request.signature_algorithm,
    )
    measurements["server_csr_generation_http_ms"] = server_csr_metrics[
        "csr_generation_http_ms"
    ]

    server_csr_id = extract_required_field(
        server_csr_response,
        "csr_id",
        "server CSR generation",
    )

    steps.append("Server service CSR generated successfully.")

    steps.append("Gateway requests a certificate for the server service.")

    server_cert_response, server_cert_metrics = await issue_certificate(
        ca_id=ca_id,
        csr_id=server_csr_id,
        validity_days=request.validity_days,
    )
    measurements["server_certificate_issuance_http_ms"] = server_cert_metrics[
        "certificate_issuance_http_ms"
    ]

    server_certificate_id = extract_required_field(
        server_cert_response,
        "certificate_id",
        "server certificate issuance",
    )
    server_certificate_pem = extract_required_field(
        server_cert_response,
        "certificate_pem",
        "server certificate issuance",
    )

    steps.append("Server service certificate issued successfully.")

    steps.append("Gateway configures the client service identity.")

    client_config_response, client_config_metrics = await _configure_client_service(
        ca_certificate_pem=ca_certificate_pem,
        client_certificate_pem=client_certificate_pem,
        expected_server_subject=request.server_common_name,
    )
    measurements.update(client_config_metrics)

    steps.append("Client service configured successfully.")

    steps.append("Gateway configures the server service identity.")

    server_config_response, server_config_metrics = await _configure_server_service(
        ca_certificate_pem=ca_certificate_pem,
        server_certificate_pem=server_certificate_pem,
        expected_client_subject=request.client_common_name,
    )
    measurements.update(server_config_metrics)

    steps.append("Server service configured successfully.")

    client_status = await _get_client_identity_status()
    server_status = await _get_server_identity_status()

    steps.append("Gateway verified identity status of both services.")

    total_end = time.perf_counter()

    measurements["total_bootstrap_from_internal_ca_ms"] = round(
        (total_end - total_start) * 1000,
        3,
    )

    result = {
        "bootstrap_completed": True,
        "reason": (
            "Client and server services were configured with PQC X.509 "
            "certificates issued by internal-ca."
        ),
        "internal_ca": {
            "ca_id": ca_id,
            "client_csr_id": client_csr_id,
            "server_csr_id": server_csr_id,
            "client_certificate_id": client_certificate_id,
            "server_certificate_id": server_certificate_id,
            "ca_subject": ca_response.get("subject"),
            "client_subject": client_cert_response.get("subject"),
            "server_subject": server_cert_response.get("subject"),
            "signature_algorithm": request.signature_algorithm,
        },
        "client_service": {
            "configured": bool(client_status.get("configured")),
            "service_id": client_status.get("service_id", "billing-service"),
            "service_role": client_status.get("service_role", "mtls-client"),
            "expected_peer_subject": request.server_common_name,
            "status_response": client_status,
        },
        "server_service": {
            "configured": bool(server_status.get("configured")),
            "service_id": server_status.get("service_id", "customer-api"),
            "service_role": server_status.get("service_role", "mtls-server"),
            "expected_peer_subject": request.client_common_name,
            "status_response": server_status,
        },
        "steps": steps,
        "measurements": measurements,
    }

    LATEST_BOOTSTRAP_STATE["bootstrap_completed"] = True
    LATEST_BOOTSTRAP_STATE["latest_bootstrap"] = result

    return result


async def get_bootstrap_status() -> Dict[str, Any]:
    """
    Return the latest known bootstrap status from the gateway point of view.
    """

    client_status: Dict[str, Any]
    server_status: Dict[str, Any]

    try:
        client_status = await _get_client_identity_status()
    except Exception as exc:
        client_status = {
            "configured": False,
            "reachable": False,
            "error": str(exc),
        }

    try:
        server_status = await _get_server_identity_status()
    except Exception as exc:
        server_status = {
            "configured": False,
            "reachable": False,
            "error": str(exc),
        }

    bootstrap_completed = bool(
        LATEST_BOOTSTRAP_STATE.get("bootstrap_completed")
        and client_status.get("configured")
        and server_status.get("configured")
    )

    if bootstrap_completed:
        reason = "Distributed mTLS services are configured and ready."
    else:
        reason = "Distributed mTLS services are not fully configured yet."

    latest_bootstrap = LATEST_BOOTSTRAP_STATE.get("latest_bootstrap")

    return {
        "bootstrap_completed": bootstrap_completed,
        "reason": reason,
        "gateway": {
            "service": settings.SERVICE_NAME,
            "client_service_url": settings.CLIENT_SERVICE_URL,
            "server_service_url": settings.SERVER_SERVICE_URL,
            "internal_ca_url": settings.INTERNAL_CA_URL,
        },
        "internal_ca": (
            latest_bootstrap.get("internal_ca", {})
            if latest_bootstrap
            else {}
        ),
        "client_service": client_status,
        "server_service": server_status,
        "latest_bootstrap": latest_bootstrap,
    }