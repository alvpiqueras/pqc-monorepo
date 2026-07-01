from __future__ import annotations

import time
from typing import Any, Dict

import httpx

from core.config import settings


def _internal_headers() -> dict[str, str]:
    return {
        "X-MTLS-Demo-Token": settings.INTERNAL_DEMO_TOKEN,
    }


async def check_distributed_connectivity() -> Dict[str, Any]:
    """
    Check that the gateway can reach both internal mTLS demo services.
    """

    total_start = time.perf_counter()

    async with httpx.AsyncClient(timeout=10.0) as client:
        client_start = time.perf_counter()
        client_response = await client.get(
            f"{settings.CLIENT_SERVICE_URL}/client/info",
            headers=_internal_headers(),
        )
        client_end = time.perf_counter()

        server_start = time.perf_counter()
        server_response = await client.get(
            f"{settings.SERVER_SERVICE_URL}/server/info",
            headers=_internal_headers(),
        )
        server_end = time.perf_counter()

    total_end = time.perf_counter()

    return {
        "gateway": {
            "service": settings.SERVICE_NAME,
            "version": settings.SERVICE_VERSION,
            "role": settings.COMPONENT_ROLE,
            "client_service_url": settings.CLIENT_SERVICE_URL,
            "server_service_url": settings.SERVER_SERVICE_URL,
            "internal_ca_url": settings.INTERNAL_CA_URL,
        },
        "client_service": {
            "reachable": client_response.status_code == 200,
            "status_code": client_response.status_code,
            "response": client_response.json(),
            "latency_ms": round((client_end - client_start) * 1000, 3),
        },
        "server_service": {
            "reachable": server_response.status_code == 200,
            "status_code": server_response.status_code,
            "response": server_response.json(),
            "latency_ms": round((server_end - server_start) * 1000, 3),
        },
        "measurements": {
            "total_connectivity_check_ms": round(
                (total_end - total_start) * 1000,
                3,
            )
        },
    }