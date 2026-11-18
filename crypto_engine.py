"""
CNS Cryptographic Engine
Supports:
- RSA 2048-bit Key Pair Generation
- Protocol 1 (CP1): Pure RSA Asymmetric Chunked Encryption & Decryption
- Protocol 2 (CP2): Hybrid Encryption (AES-256-GCM + RSA-2048 Key Envelope)
- SHA-256 Checksum for Data Integrity
- Benchmarking between CP1 and CP2
"""

import os
import time
import base64
import hashlib
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Key Generation & Serialization
# ---------------------------------------------------------------------------

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """Generates an RSA key pair and returns PEM strings (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return private_pem, public_pem


def load_private_key(pem_str: str):
    return serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)


def load_public_key(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def compute_sha256(data: bytes) -> str:
    """Computes hexadecimal SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()

# ---------------------------------------------------------------------------
# Protocol 2 (CP2): Hybrid AES-256-GCM + RSA Envelope Encryption
# ---------------------------------------------------------------------------

def encrypt_cp2_hybrid(data: bytes, public_key_pem: str) -> Dict[str, Any]:
    """
    CP2: Hybrid Encryption
    1. Generates a fresh 256-bit AES key.
    2. Encrypts data with AES-256-GCM (authenticated encryption with 96-bit nonce).
    3. Encrypts the AES key using RSA OAEP (Envelope Encryption).
    """
    start_time = time.perf_counter()
    public_key = load_public_key(public_key_pem)

    # 1. Generate 256-bit AES Key & 96-bit Nonce
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM

    # 2. Encrypt payload with AES-GCM
    ciphertext = aesgcm.encrypt(nonce, data, None)

    # 3. Encrypt AES Key with RSA OAEP
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return {
        "protocol": "CP2-Hybrid (AES-256-GCM + RSA-2048)",
        "ciphertext": ciphertext,
        "encrypted_key_b64": base64.b64encode(encrypted_aes_key).decode("utf-8"),
        "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "sha256": compute_sha256(data),
        "plain_size": len(data),
        "cipher_size": len(ciphertext),
        "encrypt_time_ms": round(elapsed_ms, 2)
    }


def decrypt_cp2_hybrid(ciphertext: bytes, encrypted_key_b64: str, nonce_b64: str, private_key_pem: str) -> Tuple[bytes, float]:
    """Decrypts CP2 payload using RSA private key and AES-GCM."""
    start_time = time.perf_counter()
    private_key = load_private_key(private_key_pem)

    # 1. Decrypt AES Key using RSA
    encrypted_aes_key = base64.b64decode(encrypted_key_b64)
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2. Decrypt Ciphertext using AES-GCM
    nonce = base64.b64decode(nonce_b64)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    return plaintext, round(elapsed_ms, 2)

# ---------------------------------------------------------------------------
# Protocol 1 (CP1): Pure Asymmetric RSA Chunked Encryption
# ---------------------------------------------------------------------------

def encrypt_cp1_rsa(data: bytes, public_key_pem: str) -> Dict[str, Any]:
    """
    CP1: Pure RSA Chunked Encryption
    Chunk size: 190 bytes for RSA-2048 with OAEP SHA-256 (256 - 2*32 - 2 = 190 bytes).
    Each chunk encrypts to 256 bytes.
    """
    start_time = time.perf_counter()
    public_key = load_public_key(public_key_pem)

    chunk_size = 190
    encrypted_chunks = []

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        enc_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(enc_chunk)

    ciphertext = b"".join(encrypted_chunks)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return {
        "protocol": "CP1-RSA (Pure Asymmetric Chunked)",
        "ciphertext": ciphertext,
        "encrypted_key_b64": "",
        "nonce_b64": "",
        "sha256": compute_sha256(data),
        "plain_size": len(data),
        "cipher_size": len(ciphertext),
        "encrypt_time_ms": round(elapsed_ms, 2)
    }


def decrypt_cp1_rsa(ciphertext: bytes, private_key_pem: str) -> Tuple[bytes, float]:
    """Decrypts CP1 pure RSA payload in 256-byte chunks."""
    start_time = time.perf_counter()
    private_key = load_private_key(private_key_pem)

    rsa_block_size = 256  # 2048 bits = 256 bytes
    decrypted_chunks = []

    for i in range(0, len(ciphertext), rsa_block_size):
        block = ciphertext[i:i + rsa_block_size]
        chunk = private_key.decrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(chunk)

    plaintext = b"".join(decrypted_chunks)
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    return plaintext, round(elapsed_ms, 2)

# ---------------------------------------------------------------------------
# Benchmark Utility
# ---------------------------------------------------------------------------

def run_crypto_benchmark(sample_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Runs both CP1 and CP2 on given data and returns comparative performance metrics."""
    priv_pem, pub_pem = generate_rsa_keypair(2048)

    # Test CP2 (Hybrid AES+RSA)
    cp2_enc = encrypt_cp2_hybrid(sample_bytes, pub_pem)
    cp2_dec, cp2_dec_time = decrypt_cp2_hybrid(
        cp2_enc["ciphertext"], cp2_enc["encrypted_key_b64"], cp2_enc["nonce_b64"], priv_pem
    )
    cp2_verified = (compute_sha256(cp2_dec) == cp2_enc["sha256"])

    # Test CP1 (Pure RSA) - limit to 100KB for CP1 if file is huge to avoid seconds of CPU block
    can_run_cp1 = len(sample_bytes) <= 250_000
    if can_run_cp1:
        cp1_enc = encrypt_cp1_rsa(sample_bytes, pub_pem)
        cp1_dec, cp1_dec_time = decrypt_cp1_rsa(cp1_enc["ciphertext"], priv_pem)
        cp1_verified = (compute_sha256(cp1_dec) == cp1_enc["sha256"])
        cp1_data = {
            "encrypt_time_ms": cp1_enc["encrypt_time_ms"],
            "decrypt_time_ms": cp1_dec_time,
            "total_time_ms": round(cp1_enc["encrypt_time_ms"] + cp1_dec_time, 2),
            "cipher_size": cp1_enc["cipher_size"],
            "verified": cp1_verified
        }
    else:
        cp1_data = {
            "skipped": True,
            "reason": f"File size ({len(sample_bytes)/1024:.1f} KB) is too large for Pure RSA. CP1 would take minutes due to $O(N)$ asymmetric modular exponentiation!"
        }

    return {
        "file_name": file_name,
        "file_size_bytes": len(sample_bytes),
        "cp2_hybrid": {
            "encrypt_time_ms": cp2_enc["encrypt_time_ms"],
            "decrypt_time_ms": cp2_dec_time,
            "total_time_ms": round(cp2_enc["encrypt_time_ms"] + cp2_dec_time, 2),
            "cipher_size": cp2_enc["cipher_size"],
            "verified": cp2_verified
        },
        "cp1_rsa": cp1_data
    }
