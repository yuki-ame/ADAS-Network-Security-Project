"""
crypto_utils.py — HMAC-SHA256 sign/verify helpers for CAN frames.

Standard CAN data frames carry at most 8 bytes, so the HMAC must be
truncated.  We use the first N bytes of HMAC-SHA256:
  - 2 bytes for radar frames  (6 data bytes + 2 HMAC = 8)
  - 4 bytes for all others    (4 data bytes + 4 HMAC = 8)

This trade-off reduces cryptographic strength but is a realistic
constraint in automotive CAN networks.
"""

import hmac
import hashlib

from common.can_ids import HMAC_KEY, HMAC_LEN_LONG


def compute_hmac(data: bytes, key: bytes = HMAC_KEY, truncate: int = HMAC_LEN_LONG) -> bytes:
    """
    Compute a truncated HMAC-SHA256 over the given data.

    Args:
        data:     The payload bytes to authenticate (everything before the HMAC).
        key:      The shared secret key (defaults to the project-wide key).
        truncate: Number of leading bytes to keep from the full 32-byte HMAC.

    Returns:
        The first `truncate` bytes of HMAC-SHA256(key, data).
    """
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()[:truncate]


def verify_hmac(data: bytes, received_hmac: bytes, key: bytes = HMAC_KEY, truncate: int = HMAC_LEN_LONG) -> bool:
    """
    Verify a received truncated HMAC against the expected value.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing side-channel attacks.

    Args:
        data:          The payload bytes (everything before the HMAC).
        received_hmac: The HMAC bytes extracted from the CAN frame.
        key:           The shared secret key.
        truncate:      Expected length of the truncated HMAC.

    Returns:
        True if the HMAC matches, False otherwise.
    """
    expected = compute_hmac(data, key, truncate)
    return hmac.compare_digest(expected, received_hmac)


def sign_payload(data: bytes, truncate: int = HMAC_LEN_LONG, key: bytes = HMAC_KEY) -> bytes:
    """
    Convenience: append a truncated HMAC to the data payload.

    Args:
        data:     Raw payload bytes (seq + fields).
        truncate: HMAC truncation length.
        key:      Shared secret.

    Returns:
        data + HMAC  (ready to go into a CAN message's data field).
    """
    mac = compute_hmac(data, key, truncate)
    return data + mac


def split_and_verify(frame_data: bytes, hmac_len: int, key: bytes = HMAC_KEY) -> tuple[bytes, bytes, bool]:
    """
    Split a CAN frame's data field into (payload, hmac, is_valid).

    Args:
        frame_data: The full 8-byte CAN data field.
        hmac_len:   Number of trailing bytes that are the HMAC.
        key:        Shared secret.

    Returns:
        (payload_bytes, hmac_bytes, is_valid)
    """
    split_at = len(frame_data) - hmac_len
    payload = frame_data[:split_at]
    mac     = frame_data[split_at:]
    valid   = verify_hmac(payload, mac, key, hmac_len)
    return payload, mac, valid
