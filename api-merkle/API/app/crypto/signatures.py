from __future__ import annotations

import base64
from typing import Dict, List

import oqs


DEFAULT_SIG_ALGORITHM = "ML-DSA-65"


def get_enabled_signature_algorithms() -> List[str]:
    """
    Devuelve la lista de mecanismos de firma habilitados en liboqs.
    """
    return list(oqs.get_enabled_sig_mechanisms())


def is_algorithm_enabled(algorithm: str) -> bool:
    """
    Comprueba si un algoritmo de firma está habilitado.
    """
    return algorithm in get_enabled_signature_algorithms()


def _ensure_algorithm_enabled(algorithm: str) -> None:
    """
    Lanza una excepción si el algoritmo no está disponible.
    """
    if not is_algorithm_enabled(algorithm):
        available = ", ".join(get_enabled_signature_algorithms())
        raise ValueError(
            f"El algoritmo '{algorithm}' no está habilitado en liboqs. "
            f"Disponibles: {available}"
        )


def bytes_to_base64(data: bytes) -> str:
    """
    Convierte bytes a Base64 UTF-8.
    """
    return base64.b64encode(data).decode("utf-8")


def base64_to_bytes(data_b64: str) -> bytes:
    """
    Convierte una cadena Base64 a bytes.
    """
    return base64.b64decode(data_b64.encode("utf-8"))


def generate_signature_keypair(algorithm: str = DEFAULT_SIG_ALGORITHM) -> Dict[str, str]:
    """
    Genera un par de claves para firma PQC.

    Devuelve:
    {
        "algorithm": "...",
        "public_key_b64": "...",
        "secret_key_b64": "..."
    }
    """
    _ensure_algorithm_enabled(algorithm)

    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    return {
        "algorithm": algorithm,
        "public_key_b64": bytes_to_base64(public_key),
        "secret_key_b64": bytes_to_base64(secret_key),
    }


def sign_message(
    message: bytes,
    secret_key_b64: str,
    algorithm: str = DEFAULT_SIG_ALGORITHM,
) -> str:
    """
    Firma un mensaje binario y devuelve la firma en Base64.
    """
    _ensure_algorithm_enabled(algorithm)

    secret_key = base64_to_bytes(secret_key_b64)

    with oqs.Signature(algorithm, secret_key) as signer:
        signature = signer.sign(message)

    return bytes_to_base64(signature)


def verify_signature(
    message: bytes,
    signature_b64: str,
    public_key_b64: str,
    algorithm: str = DEFAULT_SIG_ALGORITHM,
) -> bool:
    """
    Verifica una firma PQC sobre un mensaje binario.
    """
    _ensure_algorithm_enabled(algorithm)

    signature = base64_to_bytes(signature_b64)
    public_key = base64_to_bytes(public_key_b64)

    with oqs.Signature(algorithm) as verifier:
        return verifier.verify(message, signature, public_key)


def sign_text(
    text: str,
    secret_key_b64: str,
    algorithm: str = DEFAULT_SIG_ALGORITHM,
) -> str:
    """
    Firma un texto UTF-8 y devuelve la firma en Base64.
    """
    return sign_message(
        message=text.encode("utf-8"),
        secret_key_b64=secret_key_b64,
        algorithm=algorithm,
    )


def verify_text_signature(
    text: str,
    signature_b64: str,
    public_key_b64: str,
    algorithm: str = DEFAULT_SIG_ALGORITHM,
) -> bool:
    """
    Verifica una firma PQC sobre un texto UTF-8.
    """
    return verify_signature(
        message=text.encode("utf-8"),
        signature_b64=signature_b64,
        public_key_b64=public_key_b64,
        algorithm=algorithm,
    )


def sign_root_hash(
    root_hash: str,
    secret_key_b64: str,
    algorithm: str = DEFAULT_SIG_ALGORITHM,
) -> str:
    """
    Firma la raíz del árbol de Merkle.

    root_hash se trata como texto hexadecimal UTF-8.
    """
    return sign_text(
        text=root_hash,
        secret_key_b64=secret_key_b64,
        algorithm=algorithm,
    )


def verify_root_hash_signature(
    root_hash: str,
    signature_b64: str,
    public_key_b64: str,
    algorithm: str = DEFAULT_SIG_ALGORITHM,
) -> bool:
    """
    Verifica la firma de la raíz del árbol de Merkle.
    """
    return verify_text_signature(
        text=root_hash,
        signature_b64=signature_b64,
        public_key_b64=public_key_b64,
        algorithm=algorithm,
    )