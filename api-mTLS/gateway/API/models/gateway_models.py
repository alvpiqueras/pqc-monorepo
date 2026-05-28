from typing import Any, Dict

from pydantic import BaseModel


class ConnectivityCheckResponse(BaseModel):
    gateway: Dict[str, Any]
    client_service: Dict[str, Any]
    server_service: Dict[str, Any]