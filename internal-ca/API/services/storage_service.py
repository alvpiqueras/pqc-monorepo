import uuid
from pathlib import Path

from core.config import settings


def ensure_storage_dirs() -> None:
    """
    Create the storage directories required by the internal CA.

    The current implementation stores generated keys, CSRs and certificates
    in the container filesystem. This is suitable for an academic demo, but
    production systems would need persistent and protected storage.
    """

    settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    settings.KEYS_DIR.mkdir(parents=True, exist_ok=True)
    settings.CSRS_DIR.mkdir(parents=True, exist_ok=True)
    settings.CERTIFICATES_DIR.mkdir(parents=True, exist_ok=True)


def new_ca_id() -> str:
    return f"ca-{uuid.uuid4().hex[:12]}"


def new_csr_id() -> str:
    return f"csr-{uuid.uuid4().hex[:12]}"


def new_certificate_id() -> str:
    return f"cert-{uuid.uuid4().hex[:12]}"


def ca_key_path(ca_id: str) -> Path:
    return settings.KEYS_DIR / f"{ca_id}.key.pem"


def ca_cert_path(ca_id: str) -> Path:
    return settings.CERTIFICATES_DIR / f"{ca_id}.cert.pem"


def service_key_path(csr_id: str) -> Path:
    return settings.KEYS_DIR / f"{csr_id}.key.pem"


def csr_path(csr_id: str) -> Path:
    return settings.CSRS_DIR / f"{csr_id}.csr.pem"


def issued_cert_path(certificate_id: str) -> Path:
    return settings.CERTIFICATES_DIR / f"{certificate_id}.cert.pem"


def serial_path(ca_id: str) -> Path:
    return settings.CERTIFICATES_DIR / f"{ca_id}.srl"


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def assert_file_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found at path: {path}")