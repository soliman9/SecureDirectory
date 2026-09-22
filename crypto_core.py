"""
crypto_core.py
Phase 1 - The Cryptography Core

Handles:
  * Deriving a secure 256-bit key from a human password (PBKDF2HMAC-SHA256)
  * Encrypting / decrypting a whole blob in memory with Fernet
  * Encrypting / decrypting a file in fixed-size chunks with AES-256-GCM,
    for folders too large to comfortably hold in RAM

The password itself is NEVER written to disk anywhere. Only the random
salt generated for each encryption is stored (in plaintext) - the salt is
not secret, it only needs to be unique per encryption so the same password
never derives the same key twice.
"""

import base64
import os
import struct

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Tunable security parameters -------------------------------------------
SALT_SIZE = 16                  # bytes, random per encryption, stored in plaintext
KEY_SIZE = 32                    # 256-bit key
PBKDF2_ITERATIONS = 480_000      # OWASP 2023 minimum recommendation for PBKDF2-HMAC-SHA256
GCM_NONCE_SIZE = 12               # 96-bit nonce, the standard size for AES-GCM
STREAM_CHUNK_SIZE = 64 * 1024      # 64 KiB plaintext per streamed chunk


def derive_raw_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a raw 32-byte key from a password + salt via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_fernet_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a urlsafe-base64 key in the shape Fernet expects."""
    raw = derive_raw_key(password, salt, iterations)
    return base64.urlsafe_b64encode(raw)


# --- Mode 1: Fernet, whole payload in memory --------------------------------

def fernet_encrypt(data: bytes, password: str, salt: bytes) -> bytes:
    key = derive_fernet_key(password, salt)
    return Fernet(key).encrypt(data)


def fernet_decrypt(token: bytes, password: str, salt: bytes) -> bytes:
    key = derive_fernet_key(password, salt)
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken as exc:
        raise ValueError("Decryption failed: wrong password or corrupted file.") from exc


# --- Mode 2: AES-256-GCM, streamed in fixed-size chunks ---------------------
#
# On-disk frame layout, repeated until EOF:
#   [4 bytes big-endian frame length] [12-byte nonce][ciphertext + 16-byte tag]
#
# Every chunk gets its own random nonce, so nonce reuse (which would be
# catastrophic for GCM) is not a concern even across many chunks.

def stream_encrypt_file(src_path: str, dst_file, password: str, salt: bytes,
                         chunk_size: int = STREAM_CHUNK_SIZE) -> None:
    """Encrypt src_path in chunks, writing framed ciphertext to the open dst_file."""
    aesgcm = AESGCM(derive_raw_key(password, salt))
    with open(src_path, "rb") as src:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            nonce = os.urandom(GCM_NONCE_SIZE)
            ciphertext = aesgcm.encrypt(nonce, chunk, None)
            frame = nonce + ciphertext
            dst_file.write(struct.pack(">I", len(frame)))
            dst_file.write(frame)


def stream_decrypt_file(src_file, dst_path: str, password: str, salt: bytes) -> None:
    """Reverse of stream_encrypt_file. Reads framed ciphertext from the open
    src_file (positioned right after the header) until EOF."""
    aesgcm = AESGCM(derive_raw_key(password, salt))
    with open(dst_path, "wb") as dst:
        while True:
            len_bytes = src_file.read(4)
            if not len_bytes:
                break
            if len(len_bytes) < 4:
                raise ValueError("Corrupted vault file: truncated frame length.")
            frame_len = struct.unpack(">I", len_bytes)[0]
            frame = src_file.read(frame_len)
            if len(frame) < frame_len:
                raise ValueError("Corrupted vault file: truncated frame.")
            nonce, ciphertext = frame[:GCM_NONCE_SIZE], frame[GCM_NONCE_SIZE:]
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as exc:
                raise ValueError("Decryption failed: wrong password or corrupted file.") from exc
            dst.write(plaintext)
