import subprocess
import time
from pathlib import Path
from typing import List

from core.config import settings
from models.certificate_models import (
    GenerateCaRequest,
    GenerateCsrRequest,
    IssueCertificateRequest,
    VerifyCertificateRequest,
)
from services.storage_service import (
    assert_file_exists,
    ca_cert_path,
    ca_key_path,
    csr_path,
    external_csr_path,
    ensure_storage_dirs,
    issued_cert_path,
    new_ca_id,
    new_certificate_id,
    new_csr_id,
    read_text_file,
    serial_path,
    service_key_path,
)


def _run_openssl_command(command: List[str]) -> subprocess.CompletedProcess[str]:
    """
    Execute an OpenSSL command and return the completed process.

    Raises RuntimeError if OpenSSL returns a non-zero exit code.
    """

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "OpenSSL command failed.\n"
            f"Command: {' '.join(command)}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

    return result


def _build_subject(common_name: str, organization: str, country: str) -> str:
    """
    Build an OpenSSL subject string.
    """

    return f"/CN={common_name}/O={organization}/C={country}"


def generate_internal_ca(request: GenerateCaRequest) -> dict:
    """
    Generate an internal PQC CA.

    This creates:
    - a post-quantum private key;
    - a self-signed X.509 CA certificate.
    """

    ensure_storage_dirs()

    ca_id = new_ca_id()
    key_path = ca_key_path(ca_id)
    cert_path = ca_cert_path(ca_id)

    subject = _build_subject(
        common_name=request.common_name,
        organization=request.organization,
        country=request.country,
    )

    _run_openssl_command(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            request.signature_algorithm,
            "-out",
            str(key_path),
        ]
    )

    _run_openssl_command(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(key_path),
            "-out",
            str(cert_path),
            "-subj",
            subject,
            "-days",
            str(request.validity_days),
        ]
    )

    return {
        "ca_id": ca_id,
        "common_name": request.common_name,
        "subject": subject,
        "signature_algorithm": request.signature_algorithm,
        "private_key_path": str(key_path),
        "certificate_path": str(cert_path),
        "certificate_pem": read_text_file(cert_path),
        "message": "Internal PQC CA generated successfully.",
    }


def generate_service_csr(request: GenerateCsrRequest) -> dict:
    """
    Generate a service keypair and CSR.

    This simulates a service requesting a certificate from the internal CA.
    """

    ensure_storage_dirs()

    csr_id = new_csr_id()
    key_path = service_key_path(csr_id)
    request_path = csr_path(csr_id)

    subject = _build_subject(
        common_name=request.common_name,
        organization=request.organization,
        country=request.country,
    )

    _run_openssl_command(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            request.signature_algorithm,
            "-out",
            str(key_path),
        ]
    )

    _run_openssl_command(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            str(key_path),
            "-out",
            str(request_path),
            "-subj",
            subject,
        ]
    )

    return {
        "csr_id": csr_id,
        "common_name": request.common_name,
        "subject": subject,
        "signature_algorithm": request.signature_algorithm,
        "private_key_path": str(key_path),
        "csr_path": str(request_path),
        "csr_pem": read_text_file(request_path),
        "message": "Service PQC keypair and CSR generated successfully.",
    }


def issue_certificate_from_csr(request: IssueCertificateRequest) -> dict:
    """
    Issue an X.509 certificate from a previously generated CSR.

    The certificate is signed by the selected internal PQC CA.
    """

    ensure_storage_dirs()

    ca_certificate_path = ca_cert_path(request.ca_id)
    ca_private_key_path = ca_key_path(request.ca_id)
    request_path = csr_path(request.csr_id)

    assert_file_exists(ca_certificate_path, "CA certificate")
    assert_file_exists(ca_private_key_path, "CA private key")
    assert_file_exists(request_path, "CSR")

    certificate_id = new_certificate_id()
    certificate_path = issued_cert_path(certificate_id)

    _run_openssl_command(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request_path),
            "-CA",
            str(ca_certificate_path),
            "-CAkey",
            str(ca_private_key_path),
            "-CAserial",
            str(serial_path(request.ca_id)),
            "-CAcreateserial",
            "-out",
            str(certificate_path),
            "-days",
            str(request.validity_days),
        ]
    )

    return {
        "certificate_id": certificate_id,
        "ca_id": request.ca_id,
        "csr_id": request.csr_id,
        "certificate_path": str(certificate_path),
        "certificate_pem": read_text_file(certificate_path),
        "message": "X.509 PQC certificate issued successfully.",
    }


def verify_certificate(request: VerifyCertificateRequest) -> dict:
    """
    Verify an issued certificate against the internal CA certificate.
    """

    ensure_storage_dirs()

    ca_certificate_path = ca_cert_path(request.ca_id)
    certificate_path = issued_cert_path(request.certificate_id)

    assert_file_exists(ca_certificate_path, "CA certificate")
    assert_file_exists(certificate_path, "Issued certificate")

    result = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(ca_certificate_path),
            str(certificate_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    valid = result.returncode == 0

    return {
        "valid": valid,
        "ca_id": request.ca_id,
        "certificate_id": request.certificate_id,
        "reason": (
            "Certificate verified successfully against the internal CA."
            if valid
            else "Certificate verification failed."
        ),
        "openssl_output": result.stdout or result.stderr,
    }


def inspect_certificate(certificate_id: str) -> dict:
    """
    Return the human-readable OpenSSL representation of a certificate.
    """

    certificate_path = issued_cert_path(certificate_id)
    assert_file_exists(certificate_path, "Issued certificate")

    result = _run_openssl_command(
        [
            "openssl",
            "x509",
            "-in",
            str(certificate_path),
            "-text",
            "-noout",
        ]
    )

    return {
        "certificate_id": certificate_id,
        "certificate_text": result.stdout,
    }


def get_certificate_file_path(certificate_id: str) -> Path:
    """
    Return the path to an issued certificate PEM file.
    """

    certificate_path = issued_cert_path(certificate_id)
    assert_file_exists(certificate_path, "Issued certificate")
    return certificate_path


def get_ca_certificate_file_path(ca_id: str) -> Path:
    """
    Return the path to a CA certificate PEM file.
    """

    certificate_path = ca_cert_path(ca_id)
    assert_file_exists(certificate_path, "CA certificate")
    return certificate_path


def get_csr_file_path(csr_id: str) -> Path:
    """
    Return the path to a CSR PEM file.
    """

    request_path = csr_path(csr_id)
    assert_file_exists(request_path, "CSR")
    return request_path

def issue_certificate_from_uploaded_csr_file(
    ca_id: str,
    csr_pem_bytes: bytes,
    validity_days: int,
) -> dict:
    """
    Issue an X.509 certificate from an uploaded CSR PEM file.

    This models the realistic PKI flow where an external service keeps its
    private key locally and sends only the CSR file to the internal CA.
    """

    ensure_storage_dirs()

    ca_certificate_path = ca_cert_path(ca_id)
    ca_private_key_path = ca_key_path(ca_id)

    assert_file_exists(ca_certificate_path, "CA certificate")
    assert_file_exists(ca_private_key_path, "CA private key")

    uploaded_csr_id = new_csr_id()
    request_path = external_csr_path(uploaded_csr_id)

    request_path.write_bytes(csr_pem_bytes)

    # Validate CSR before issuing a certificate.
    _run_openssl_command(
        [
            "openssl",
            "req",
            "-in",
            str(request_path),
            "-noout",
            "-verify",
        ]
    )

    certificate_id = new_certificate_id()
    certificate_path = issued_cert_path(certificate_id)

    _run_openssl_command(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request_path),
            "-CA",
            str(ca_certificate_path),
            "-CAkey",
            str(ca_private_key_path),
            "-CAserial",
            str(serial_path(ca_id)),
            "-CAcreateserial",
            "-out",
            str(certificate_path),
            "-days",
            str(validity_days),
        ]
    )

    return {
        "certificate_id": certificate_id,
        "ca_id": ca_id,
        "uploaded_csr_id": uploaded_csr_id,
        "certificate_path": str(certificate_path),
        "certificate_pem": read_text_file(certificate_path),
        "message": "X.509 PQC certificate issued successfully from uploaded CSR file.",
    }

def _measure_ms(start_time: float) -> float:
    """
    Return elapsed time in milliseconds.
    """

    return round((time.perf_counter() - start_time) * 1000, 4)


def get_file_size_bytes(path: Path) -> int:
    """
    Return file size in bytes.
    """

    assert_file_exists(path, "File")
    return path.stat().st_size


def run_ca_metrics_demo(
    signature_algorithm: str = "ML-DSA-65",
    validity_days: int = 365,
) -> dict:
    """
    Run a full temporary CA flow and collect timing and size metrics.

    Flow:
    - generate internal CA;
    - generate service CSR;
    - issue X.509 certificate;
    - verify issued certificate;
    - collect PEM file sizes.

    This endpoint is intended for academic benchmarking, not production
    performance measurement.
    """

    total_start = time.perf_counter()

    ca_start = time.perf_counter()
    ca_result = generate_internal_ca(
        GenerateCaRequest(
            common_name="Metrics Demo Internal PQC CA",
            organization="TFM PQC Lab",
            country="ES",
            signature_algorithm=signature_algorithm,
            validity_days=validity_days,
        )
    )
    ca_generation_ms = _measure_ms(ca_start)

    csr_start = time.perf_counter()
    csr_result = generate_service_csr(
        GenerateCsrRequest(
            common_name="metrics-demo-service.local",
            organization="TFM PQC Lab",
            country="ES",
            signature_algorithm=signature_algorithm,
        )
    )
    csr_generation_ms = _measure_ms(csr_start)

    issue_start = time.perf_counter()
    cert_result = issue_certificate_from_csr(
        IssueCertificateRequest(
            ca_id=ca_result["ca_id"],
            csr_id=csr_result["csr_id"],
            validity_days=validity_days,
        )
    )
    certificate_issuance_ms = _measure_ms(issue_start)

    verify_start = time.perf_counter()
    verify_result = verify_certificate(
        VerifyCertificateRequest(
            ca_id=ca_result["ca_id"],
            certificate_id=cert_result["certificate_id"],
        )
    )
    certificate_verification_ms = _measure_ms(verify_start)

    ca_certificate_path = ca_cert_path(ca_result["ca_id"])
    csr_file_path = csr_path(csr_result["csr_id"])
    issued_certificate_path = issued_cert_path(cert_result["certificate_id"])

    return {
        "signature_algorithm": signature_algorithm,
        "validity_days": validity_days,
        "timings_ms": {
            "ca_generation": ca_generation_ms,
            "csr_generation": csr_generation_ms,
            "certificate_issuance": certificate_issuance_ms,
            "certificate_verification": certificate_verification_ms,
            "total_flow": _measure_ms(total_start),
        },
        "sizes_bytes": {
            "ca_certificate_pem": get_file_size_bytes(ca_certificate_path),
            "service_csr_pem": get_file_size_bytes(csr_file_path),
            "issued_certificate_pem": get_file_size_bytes(issued_certificate_path),
        },
        "identifiers": {
            "ca_id": ca_result["ca_id"],
            "csr_id": csr_result["csr_id"],
            "certificate_id": cert_result["certificate_id"],
        },
        "verification_valid": bool(verify_result["valid"]),
        "notes": [
            "Metrics are generated dynamically for a complete temporary CA flow.",
            "Values may vary depending on CPU load, Docker runtime and hosting environment.",
            "PEM sizes reflect the encoded X.509/CSR artifacts, not only raw key or signature sizes.",
        ],
    }