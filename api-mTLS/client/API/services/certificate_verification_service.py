from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_temp_pem(directory: Path, filename: str, content: str) -> Path:
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    return path


def _extract_certificate_field(cert_path: Path, field: str) -> str:
    result = _run_command(
        [
            "openssl",
            "x509",
            "-in",
            str(cert_path),
            "-noout",
            field,
        ]
    )

    if result.returncode != 0:
        return result.stderr.strip()

    return result.stdout.strip()


def verify_certificate_against_ca(
    peer_certificate_pem: str,
    ca_certificate_pem: str,
    expected_subject_fragment: str,
) -> Dict[str, Any]:
    """
    Verify a peer X.509 certificate against the configured internal CA.

    This function checks two different things:
    - the certificate verifies against the configured CA;
    - the certificate subject contains the expected service identity.
    """

    total_start = time.perf_counter()

    if "-----BEGIN CERTIFICATE-----" not in peer_certificate_pem:
        raise ValueError("Peer certificate does not look like a PEM certificate.")

    if "-----BEGIN CERTIFICATE-----" not in ca_certificate_pem:
        raise ValueError("CA certificate does not look like a PEM certificate.")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        ca_path = _write_temp_pem(
            temp_path,
            "ca.cert.pem",
            ca_certificate_pem,
        )

        peer_path = _write_temp_pem(
            temp_path,
            "peer.cert.pem",
            peer_certificate_pem,
        )

        metadata_start = time.perf_counter()

        subject = _extract_certificate_field(peer_path, "-subject")
        issuer = _extract_certificate_field(peer_path, "-issuer")
        dates = _extract_certificate_field(peer_path, "-dates")

        metadata_end = time.perf_counter()

        verify_start = time.perf_counter()

        verify_result = _run_command(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca_path),
                str(peer_path),
            ]
        )

        verify_end = time.perf_counter()

    trust_chain_verified = verify_result.returncode == 0
    subject_matches_expected_identity = expected_subject_fragment in subject

    verified = trust_chain_verified and subject_matches_expected_identity

    return {
        "verified": verified,
        "trust_chain_verified": trust_chain_verified,
        "subject_matches_expected_identity": subject_matches_expected_identity,
        "expected_subject_fragment": expected_subject_fragment,
        "certificate_subject": subject,
        "certificate_issuer": issuer,
        "certificate_dates": dates,
        "openssl_verify_output": verify_result.stdout.strip(),
        "openssl_verify_error": verify_result.stderr.strip(),
        "measurements": {
            "certificate_metadata_parse_ms": round(
                (metadata_end - metadata_start) * 1000,
                3,
            ),
            "openssl_verify_ms": round(
                (verify_end - verify_start) * 1000,
                3,
            ),
            "certificate_verification_total_ms": round(
                (time.perf_counter() - total_start) * 1000,
                3,
            ),
        },
    }