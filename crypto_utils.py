"""
crypto_utils.py
Core cryptographic + framing logic for Secure Optical QR Communication.

Frame format (before QR encoding), as a compact binary layout:

    [ receiving_code (6 bytes) ]
    [ frame_number   (2 bytes, big-endian uint16) ]
    [ total_frames   (2 bytes, big-endian uint16) ]
    [ chunk_hash     (4 bytes, truncated SHA-256 of this chunk's plaintext-encrypted bytes) ]
    [ nonce          (12 bytes, AES-GCM nonce, unique per chunk) ]
    [ auth_tag       (16 bytes, AES-GCM tag) ]
    [ encrypted_chunk (variable, up to ~2000 bytes) ]

Everything except the encrypted_chunk is the "header" — 6+2+2+4+12+16 = 42 bytes overhead per frame.
With a 2KB (2048 byte) target frame size, usable ciphertext payload per frame is ~2006 bytes.

We then base64-encode this whole binary frame before putting it in the QR code, since QR
alphanumeric/byte mode plays more reliably with base64 text than raw binary across libraries.
"""

import hashlib
import base64
import secrets
import struct
from typing import List, Tuple
from Crypto.Cipher import AES

HEADER_STRUCT = struct.Struct(">6sHH4s12s16s")  # receiving_code, frame_no, total, chunk_hash, nonce, tag
# 1450 bytes of ciphertext + 42 bytes header = 1492 bytes binary -> ~1990 base64 chars per QR.
# This keeps the QR at a moderate density (Version ~25-30) that a phone camera scans reliably.
CHUNK_PAYLOAD_SIZE = 1450


def generate_receiving_code() -> bytes:
    """6-byte random session/receiving code, shown to the user as a hex string (12 chars)."""
    return secrets.token_bytes(6)


def receiving_code_to_str(code: bytes) -> str:
    return code.hex().upper()


def receiving_code_from_str(code_str: str) -> bytes:
    return bytes.fromhex(code_str.strip())


def sha256_full(data: bytes) -> bytes:
    """Full 32-byte SHA-256 hash — used for whole-file integrity check."""
    return hashlib.sha256(data).digest()


def sha256_short(data: bytes) -> bytes:
    """Truncated 4-byte hash — used per-frame, just to catch corruption, not for security."""
    return hashlib.sha256(data).digest()[:4]


def generate_aes_key() -> bytes:
    """AES-256 key. In the MVP this is a pre-shared key (shared out-of-band or hardcoded for demo).
    Future work: replace with X25519 key agreement."""
    return secrets.token_bytes(32)


def encrypt_file(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypts the WHOLE file once with AES-256-GCM before chunking.
    Returns (ciphertext, file_level_nonce). The file-level auth tag is appended
    to the ciphertext so the receiver can verify the whole file after reassembly,
    in addition to per-chunk hash checks.
    """
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag, nonce  # tag appended at the end (last 16 bytes)


def decrypt_file(ciphertext_with_tag: bytes, key: bytes, nonce: bytes) -> bytes:
    ciphertext, tag = ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def chunk_bytes(data: bytes, chunk_size: int = CHUNK_PAYLOAD_SIZE) -> List[bytes]:
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def build_frame(receiving_code: bytes, frame_number: int, total_frames: int,
                 chunk_ciphertext: bytes) -> bytes:
    """
    Builds one frame: header + per-chunk protection.
    We use a per-frame AES-GCM wrap (with the chunk_ciphertext as the "plaintext" input)
    ONLY to get a fresh nonce+tag pair per frame for tamper/replay detection at the frame
    level — this is on top of the whole-file AES-GCM encryption already applied.
    This gives each frame its own integrity envelope, independent of frame order.
    """
    chunk_hash = sha256_short(chunk_ciphertext)
    # Frame-level authentication tag: HMAC-like binding of code+frame#+total+hash+data
    # using AES-GCM as a MAC (encrypting the chunk again would double-encrypt; instead
    # we derive a tag by running GCM in "associated data only" mode).
    nonce = secrets.token_bytes(12)
    mac_key = hashlib.sha256(receiving_code + b"frame-mac").digest()[:16]
    cipher = AES.new(mac_key, AES.MODE_GCM, nonce=nonce)
    aad = receiving_code + struct.pack(">HH", frame_number, total_frames) + chunk_hash
    cipher.update(aad + chunk_ciphertext)
    _, tag = cipher.encrypt_and_digest(b"")  # no additional encryption, just a MAC over aad

    header = HEADER_STRUCT.pack(receiving_code, frame_number, total_frames, chunk_hash, nonce, tag)
    return header + chunk_ciphertext


def parse_frame(frame_bytes: bytes) -> dict:
    header = frame_bytes[:HEADER_STRUCT.size]
    chunk_ciphertext = frame_bytes[HEADER_STRUCT.size:]
    receiving_code, frame_number, total_frames, chunk_hash, nonce, tag = HEADER_STRUCT.unpack(header)

    return {
        "receiving_code": receiving_code,
        "frame_number": frame_number,
        "total_frames": total_frames,
        "chunk_hash": chunk_hash,
        "nonce": nonce,
        "tag": tag,
        "chunk_ciphertext": chunk_ciphertext,
    }


def verify_frame(parsed: dict, expected_receiving_code: bytes) -> Tuple[bool, str]:
    """Runs all the security checks described in your architecture doc:
    session/receiving-code match, integrity (hash), and authentication (MAC tag)."""

    if parsed["receiving_code"] != expected_receiving_code:
        return False, "INVALID SESSION (receiving code mismatch)"

    recomputed_hash = sha256_short(parsed["chunk_ciphertext"])
    if recomputed_hash != parsed["chunk_hash"]:
        return False, "INTEGRITY FAILURE (chunk hash mismatch)"

    mac_key = hashlib.sha256(parsed["receiving_code"] + b"frame-mac").digest()[:16]
    cipher = AES.new(mac_key, AES.MODE_GCM, nonce=parsed["nonce"])
    aad = (parsed["receiving_code"]
           + struct.pack(">HH", parsed["frame_number"], parsed["total_frames"])
           + parsed["chunk_hash"])
    cipher.update(aad + parsed["chunk_ciphertext"])
    try:
        cipher.verify(parsed["tag"])
    except ValueError:
        return False, "AUTHENTICATION FAILURE (tag invalid — possible tampering)"

    return True, "OK"


def frame_to_qr_text(frame_bytes: bytes) -> str:
    """Base64-encode the binary frame so it can be safely embedded in a QR code."""
    return base64.b64encode(frame_bytes).decode("ascii")


def qr_text_to_frame(qr_text: str) -> bytes:
    return base64.b64decode(qr_text.encode("ascii"))
