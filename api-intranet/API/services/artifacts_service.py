from __future__ import annotations

import json
import re
import secrets
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Literal

from core.config import settings

ArtifactType = Literal["ca_certificate", "server_certificate"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def _ensure_storage_dir() -> Path:
    storage_dir = Path(settings.ARTIFACT_STORAGE_DIR)
    storage_dir.mkdir(parents=True, exist_ok=True)
    return storage_dir


def _artifact_prefix(artifact_type: ArtifactType) -> str:
    if artifact_type == "ca_certificate":
        return "ca"
    if artifact_type == "server_certificate":
        return "srv"
    return "artifact"


def _generate_artifact_id(artifact_type: ArtifactType) -> str:
    prefix = _artifact_prefix(artifact_type)
    return f"{prefix}_{secrets.token_hex(8)}"


def _write_temp_pem(directory: Path, filename: str, content: str) -> Path:
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    return path


def _extract_single_line_output(command: list[str]) -> str:
    result = _run_command(command)
    return (result.stdout or result.stderr).strip()


def _parse_openssl_dates(raw_dates: str) -> dict[str, str]:
    metadata = {}

    for line in raw_dates.splitlines():
        if line.startswith("notBefore="):
            metadata["valid_from"] = line.replace("notBefore=", "").strip()
        elif line.startswith("notAfter="):
            metadata["valid_until"] = line.replace("notAfter=", "").strip()

    return metadata


def _parse_signature_algorithm(raw_text: str) -> str | None:
    match = re.search(r"Signature Algorithm:\s*([^\n]+)", raw_text)
    if not match:
        return None
    return match.group(1).strip()


def _parse_public_key_algorithm(raw_text: str) -> str | None:
    match = re.search(r"Public Key Algorithm:\s*([^\n]+)", raw_text)
    if not match:
        return None
    return match.group(1).strip()


def _extract_certificate_metadata(pem: str) -> tuple[Dict[str, str], Dict[str, float]]:
    """
    Extract human-readable metadata from an X.509 certificate using OpenSSL.

    This does not verify trust. It only parses certificate fields.
    """

    t0 = time.perf_counter()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        cert_path = _write_temp_pem(temp_path, "certificate.pem", pem)

        t_parse_start = time.perf_counter()

        subject = _extract_single_line_output(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"]
        )
        issuer = _extract_single_line_output(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-issuer"]
        )
        dates = _extract_single_line_output(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-dates"]
        )
        serial = _extract_single_line_output(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-serial"]
        )
        text = _extract_single_line_output(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-text"]
        )

        t_parse_end = time.perf_counter()

    metadata: Dict[str, str] = {
        "subject": subject,
        "issuer": issuer,
        "serial_number": serial.replace("serial=", "").strip(),
    }

    metadata.update(_parse_openssl_dates(dates))

    signature_algorithm = _parse_signature_algorithm(text)
    public_key_algorithm = _parse_public_key_algorithm(text)

    if signature_algorithm:
        metadata["signature_algorithm"] = signature_algorithm

    if public_key_algorithm:
        metadata["public_key_algorithm"] = public_key_algorithm

    t1 = time.perf_counter()

    measurements = {
        "openssl_parse_ms": round((t_parse_end - t_parse_start) * 1000, 3),
        "metadata_extraction_total_ms": round((t1 - t0) * 1000, 3),
    }

    return metadata, measurements


def register_certificate_artifact(
    pem: str,
    artifact_type: ArtifactType,
) -> dict:
    """
    Register a certificate as an artifact.

    Phase A responsibility:
    - store PEM
    - extract metadata
    - generate artifact_id
    - return metadata and timing information

    It does not verify trust.
    """

    t0 = time.perf_counter()

    artifact_id = _generate_artifact_id(artifact_type)
    created_at = _utc_now()

    metadata, measurements = _extract_certificate_metadata(pem)

    storage_dir = _ensure_storage_dir()
    artifact_path = storage_dir / f"{artifact_id}.json"

    artifact = {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "pem": pem,
        "metadata": metadata,
        "created_at": created_at,
    }

    artifact_path.write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    t1 = time.perf_counter()
    measurements["artifact_registration_total_ms"] = round((t1 - t0) * 1000, 3)

    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "created_at": created_at,
        "subject": metadata.get("subject", ""),
        "issuer": metadata.get("issuer", ""),
        "valid_from": metadata.get("valid_from"),
        "valid_until": metadata.get("valid_until"),
        "serial_number": metadata.get("serial_number"),
        "signature_algorithm": metadata.get("signature_algorithm"),
        "public_key_algorithm": metadata.get("public_key_algorithm"),
        "measurements": measurements,
    }


def get_artifact(artifact_id: str) -> dict | None:
    storage_dir = _ensure_storage_dir()
    artifact_path = storage_dir / f"{artifact_id}.json"

    if not artifact_path.exists():
        return None

    return json.loads(artifact_path.read_text(encoding="utf-8"))


def list_artifacts() -> list[dict]:
    storage_dir = _ensure_storage_dir()
    artifacts = []

    for path in storage_dir.glob("*.json"):
        artifact = json.loads(path.read_text(encoding="utf-8"))
        metadata = artifact.get("metadata", {})

        artifacts.append(
            {
                "artifact_id": artifact["artifact_id"],
                "artifact_type": artifact["artifact_type"],
                "subject": metadata.get("subject", ""),
                "issuer": metadata.get("issuer", ""),
                "valid_from": metadata.get("valid_from"),
                "valid_until": metadata.get("valid_until"),
                "signature_algorithm": metadata.get("signature_algorithm"),
                "created_at": artifact["created_at"],
            }
        )

    return artifacts