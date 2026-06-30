from __future__ import annotations

import base64
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import oqs

from core.config import settings


SERVER_HANDSHAKE_SESSIONS: Dict[str, Dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cleanup_expired_sessions() -> None:
    """
    Remove old handshake sessions from the in-memory store.
    """

    now = time.time()
    ttl = settings.HANDSHAKE_SESSION_TTL_SECONDS

    expired_session_ids = [
        session_id
        for session_id, session in SERVER_HANDSHAKE_SESSIONS.items()
        if now - session.get("created_at_epoch", now) > ttl
    ]

    for session_id in expired_session_ids:
        SERVER_HANDSHAKE_SESSIONS.pop(session_id, None)


def create_kem_handshake_session(
    kem_algorithm: str,
) -> tuple[Dict[str, Any], Dict[str, float]]:
    """
    Create an ephemeral ML-KEM handshake session.

    The public key is returned to the client. The KEM object remains stored in
    memory so Phase C2 can use it to decapsulate the client ciphertext.
    """

    _cleanup_expired_sessions()

    total_start = time.perf_counter()
    session_id = str(uuid.uuid4())

    kem_start = time.perf_counter()

    try:
        kem_object = oqs.KeyEncapsulation(kem_algorithm)
        kem_public_key = kem_object.generate_keypair()

    except Exception as exc:
        raise RuntimeError(
            f"Could not create ML-KEM session with algorithm '{kem_algorithm}': {exc}"
        ) from exc

    kem_end = time.perf_counter()

    kem_public_key_b64 = base64.b64encode(kem_public_key).decode("ascii")

    session = {
        "session_id": session_id,
        "kem_algorithm": kem_algorithm,
        "kem_object": kem_object,
        "kem_public_key_b64": kem_public_key_b64,
        "kem_public_key_size_bytes": len(kem_public_key),
        "created_at": _now_iso(),
        "created_at_epoch": time.time(),
        "used": False,
        "phase": "C1-handshake-only",
    }

    SERVER_HANDSHAKE_SESSIONS[session_id] = session

    measurements = {
        "server_ml_kem_keypair_generation_ms": round(
            (kem_end - kem_start) * 1000,
            3,
        ),
        "server_handshake_session_creation_total_ms": round(
            (time.perf_counter() - total_start) * 1000,
            3,
        ),
    }

    return session, measurements


def get_handshake_session(session_id: str) -> Dict[str, Any]:
    """
    Return a stored handshake session.

    This helper is prepared for Phase C2.
    """

    _cleanup_expired_sessions()

    session = SERVER_HANDSHAKE_SESSIONS.get(session_id)

    if session is None:
        raise RuntimeError(
            "Handshake session not found or expired. Start a new handshake first."
        )

    return session


def mark_handshake_session_used(session_id: str) -> None:
    """
    Mark a session as used.

    This will be useful in Phase C2 to avoid replaying the same KEM session.
    """

    session = get_handshake_session(session_id)
    session["used"] = True