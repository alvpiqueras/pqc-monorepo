import json
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from core.config import settings


ARTIFACTS_DIR = Path("/tmp/api-interna/artifacts")
CA_CERTS_DIR = ARTIFACTS_DIR / "ca-certificates"
SERVICE_CERTS_DIR = ARTIFACTS_DIR / "service-certificates"
POLICIES_DIR = ARTIFACTS_DIR / "authorization-policies"


def ensure_artifact_dirs() -> None:
    """
    Create temporary artifact directories.

    This storage is intended for an academic demo. A production system would
    use persistent storage, authentication, authorization and audit logs.
    """

    CA_CERTS_DIR.mkdir(parents=True, exist_ok=True)
    SERVICE_CERTS_DIR.mkdir(parents=True, exist_ok=True)
    POLICIES_DIR.mkdir(parents=True, exist_ok=True)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _write_bytes(path: Path, content: bytes) -> None:
    path.write_bytes(content)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _assert_file_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found at path: {path}")


def store_ca_certificate(filename: str, content: bytes) -> Dict[str, Any]:
    ensure_artifact_dirs()

    artifact_id = _new_id("ca-art")
    safe_filename = filename or f"{artifact_id}.cert.pem"
    path = CA_CERTS_DIR / f"{artifact_id}.cert.pem"

    _write_bytes(path, content)

    return {
        "artifact_id": artifact_id,
        "artifact_type": "ca-certificate",
        "filename": safe_filename,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "message": "CA certificate artifact stored successfully.",
    }


def store_service_certificate(filename: str, content: bytes) -> Dict[str, Any]:
    ensure_artifact_dirs()

    artifact_id = _new_id("svc-cert")
    safe_filename = filename or f"{artifact_id}.cert.pem"
    path = SERVICE_CERTS_DIR / f"{artifact_id}.cert.pem"

    _write_bytes(path, content)

    return {
        "artifact_id": artifact_id,
        "artifact_type": "service-certificate",
        "filename": safe_filename,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "message": "Service certificate artifact stored successfully.",
    }


def store_authorization_policy(filename: str, content: bytes) -> Dict[str, Any]:
    ensure_artifact_dirs()

    policy_text = content.decode("utf-8")

    try:
        parsed_policy = json.loads(policy_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid authorization policy JSON: {exc}") from exc

    if not isinstance(parsed_policy, dict):
        raise ValueError("Authorization policy must be a JSON object.")

    policy_id = _new_id("policy")
    safe_filename = filename or f"{policy_id}.json"
    path = POLICIES_DIR / f"{policy_id}.json"

    _write_bytes(path, content)

    return {
        "policy_id": policy_id,
        "artifact_type": "authorization-policy",
        "filename": safe_filename,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "parsed_policy": parsed_policy,
        "message": "Authorization policy artifact stored successfully.",
    }


def get_ca_certificate_pem(ca_artifact_id: str) -> str:
    if not ca_artifact_id.startswith("ca-art-"):
        raise ValueError(
            f"Invalid CA artifact ID format: {ca_artifact_id}. "
            "Expected prefix 'ca-art-'."
        )

    path = CA_CERTS_DIR / f"{ca_artifact_id}.cert.pem"
    _assert_file_exists(path, "CA certificate artifact")
    return _read_text(path)


def get_service_certificate_pem(service_certificate_id: str) -> str:
    if not service_certificate_id.startswith("svc-cert-"):
        raise ValueError(
            f"Invalid service certificate ID format: {service_certificate_id}. "
            "Expected prefix 'svc-cert-'."
        )

    path = SERVICE_CERTS_DIR / f"{service_certificate_id}.cert.pem"
    _assert_file_exists(path, "Service certificate artifact")
    return _read_text(path)


def get_authorization_policy_json(policy_id: str) -> str:
    if not policy_id.startswith("policy-"):
        raise ValueError(
            f"Invalid policy ID format: {policy_id}. Expected prefix 'policy-'."
        )

    path = POLICIES_DIR / f"{policy_id}.json"
    _assert_file_exists(path, "Authorization policy artifact")
    return _read_text(path)


def get_artifact_info(
    artifact_id: str,
    include_preview: bool = False,
) -> Dict[str, Any]:
    """
    Return metadata for a stored artifact.

    This helper is useful for frontend debugging and step-by-step workflows.
    """

    ensure_artifact_dirs()

    if artifact_id.startswith("ca-art-"):
        artifact_type = "ca-certificate"
        path = CA_CERTS_DIR / f"{artifact_id}.cert.pem"
    elif artifact_id.startswith("svc-cert-"):
        artifact_type = "service-certificate"
        path = SERVICE_CERTS_DIR / f"{artifact_id}.cert.pem"
    elif artifact_id.startswith("policy-"):
        artifact_type = "authorization-policy"
        path = POLICIES_DIR / f"{artifact_id}.json"
    else:
        raise ValueError(f"Unknown artifact ID format: {artifact_id}")

    _assert_file_exists(path, "Artifact")

    preview: Optional[str] = None
    if include_preview:
        content = _read_text(path)
        preview = content[:1000]

    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "filename": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "preview": preview,
    }