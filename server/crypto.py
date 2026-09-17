import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = "v1"
NONCE_SIZE = 12


def load_key(key_b64: str) -> bytes:
    key = base64.b64decode(key_b64, validate=True)
    if len(key) != 32:
        raise ValueError("CLIPPYC2_ENCRYPTION_KEY must decode to 32 bytes")
    return key


def encrypt(plaintext: str, key: bytes) -> str:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = base64.b64encode(nonce + ciphertext).decode("ascii")
    return f"{VERSION}:{blob}"


def decrypt(blob: str, key: bytes) -> str:
    if not blob.startswith(f"{VERSION}:"):
        raise ValueError("Unknown or unsupported ciphertext format")
    raw = base64.b64decode(blob[len(VERSION) + 1 :], validate=True)
    if len(raw) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce, ciphertext = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
