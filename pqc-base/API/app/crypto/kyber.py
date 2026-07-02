import base64
import time

import oqs


DEFAULT_KEM = "ML-KEM-768"


def bytes_to_b64(data: bytes) -> str:
    """Convierte bytes a string Base64."""
    return base64.b64encode(data).decode("utf-8")


def b64_to_bytes(data_b64: str) -> bytes:
    """Convierte string Base64 a bytes."""
    return base64.b64decode(data_b64.encode("utf-8"), validate=True)


def generate_keypair(algorithm: str = DEFAULT_KEM) -> dict:
    """
    Genera un par de claves para ML-KEM y las devuelve en Base64.

    Measurements:
    - keypair_generation_ms: tiempo dedicado a generar el par de claves.
    - total_operation_ms: tiempo total de la función, incluyendo serialización Base64.
    """

    total_start = time.perf_counter()

    keygen_start = time.perf_counter()

    with oqs.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    keygen_end = time.perf_counter()

    public_key_b64 = bytes_to_b64(public_key)
    secret_key_b64 = bytes_to_b64(secret_key)

    total_end = time.perf_counter()

    return {
        "algorithm": algorithm,
        "public_key": public_key_b64,
        "secret_key": secret_key_b64,
        "measurements": {
            "keypair_generation_ms": round((keygen_end - keygen_start) * 1000, 3),
            "total_operation_ms": round((total_end - total_start) * 1000, 3),
        },
        "sizes_bytes": {
            "public_key": len(public_key),
            "secret_key": len(secret_key),
            "public_key_b64": len(public_key_b64.encode("utf-8")),
            "secret_key_b64": len(secret_key_b64.encode("utf-8")),
        },
    }


def encapsulate(public_key_b64: str, algorithm: str = DEFAULT_KEM) -> dict:
    """
    Encapsula un secreto compartido a partir de una clave pública.
    Devuelve ciphertext y shared_secret en Base64.

    Measurements:
    - encapsulation_ms: tiempo dedicado a la operación criptográfica de encapsulación.
    - total_operation_ms: tiempo total, incluyendo decodificación de clave pública
      y serialización Base64.
    """

    total_start = time.perf_counter()

    public_key = b64_to_bytes(public_key_b64)

    encaps_start = time.perf_counter()

    with oqs.KeyEncapsulation(algorithm) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)

    encaps_end = time.perf_counter()

    ciphertext_b64 = bytes_to_b64(ciphertext)
    shared_secret_b64 = bytes_to_b64(shared_secret)

    total_end = time.perf_counter()

    return {
        "algorithm": algorithm,
        "ciphertext": ciphertext_b64,
        "shared_secret": shared_secret_b64,
        "measurements": {
            "encapsulation_ms": round((encaps_end - encaps_start) * 1000, 3),
            "total_operation_ms": round((total_end - total_start) * 1000, 3),
        },
        "sizes_bytes": {
            "public_key": len(public_key),
            "ciphertext": len(ciphertext),
            "shared_secret": len(shared_secret),
            "ciphertext_b64": len(ciphertext_b64.encode("utf-8")),
            "shared_secret_b64": len(shared_secret_b64.encode("utf-8")),
        },
    }


def decapsulate(ciphertext_b64: str, secret_key_b64: str, algorithm: str = DEFAULT_KEM) -> dict:
    """
    Decapsula el secreto compartido a partir de ciphertext y clave privada.
    Devuelve shared_secret en Base64.

    Measurements:
    - decapsulation_ms: tiempo dedicado a la operación criptográfica de decapsulación.
    - total_operation_ms: tiempo total, incluyendo decodificación de ciphertext,
      clave privada y serialización Base64.
    """

    total_start = time.perf_counter()

    ciphertext = b64_to_bytes(ciphertext_b64)
    secret_key = b64_to_bytes(secret_key_b64)

    decaps_start = time.perf_counter()

    with oqs.KeyEncapsulation(algorithm, secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)

    decaps_end = time.perf_counter()

    shared_secret_b64 = bytes_to_b64(shared_secret)

    total_end = time.perf_counter()

    return {
        "algorithm": algorithm,
        "shared_secret": shared_secret_b64,
        "measurements": {
            "decapsulation_ms": round((decaps_end - decaps_start) * 1000, 3),
            "total_operation_ms": round((total_end - total_start) * 1000, 3),
        },
        "sizes_bytes": {
            "ciphertext": len(ciphertext),
            "secret_key": len(secret_key),
            "shared_secret": len(shared_secret),
            "shared_secret_b64": len(shared_secret_b64.encode("utf-8")),
        },
    }


if __name__ == "__main__":
    print("=== ML-KEM local test ===")

    keys = generate_keypair()
    print("Keypair generated.")
    print(keys["measurements"])
    print(keys["sizes_bytes"])

    encapsulated = encapsulate(keys["public_key"])
    print("Encapsulation done.")
    print(encapsulated["measurements"])
    print(encapsulated["sizes_bytes"])

    decapsulated = decapsulate(
        encapsulated["ciphertext"],
        keys["secret_key"],
    )
    print("Decapsulation done.")
    print(decapsulated["measurements"])
    print(decapsulated["sizes_bytes"])

    same_secret = encapsulated["shared_secret"] == decapsulated["shared_secret"]
    print(f"Shared secrets match: {same_secret}")