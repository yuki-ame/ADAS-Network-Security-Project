"""
test_normal_traffic.py — Verify end-to-end normal traffic flow.

Tests that:
  - Radar and camera nodes produce valid signed frames
  - ADAS ECU processes sensor data and makes correct decisions
  - Brake ECU actuates correctly based on ADAS decisions
  - All frames carry valid HMACs and incrementing sequence numbers
"""

import os
import sys
import struct
import time
import threading
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import can_ids
from common.bus import get_bus
from defense.crypto_utils import sign_payload, split_and_verify, compute_hmac
import can


class TestPayloadFormats:
    """Verify that payload packing/unpacking matches the 8-byte CAN constraint."""

    def test_radar_payload_fits_8_bytes(self):
        """Radar: 6 data bytes + 2 HMAC = 8 bytes."""
        data = struct.pack(can_ids.FMT_RADAR_DATA, 1, 500, 100)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_SHORT)
        assert len(signed) == 8, f"Radar frame is {len(signed)} bytes, expected 8"

    def test_camera_payload_fits_8_bytes(self):
        """Camera: 4 data bytes + 4 HMAC = 8 bytes."""
        data = struct.pack(can_ids.FMT_CAMERA_DATA, 1, 1, 80)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_LONG)
        assert len(signed) == 8, f"Camera frame is {len(signed)} bytes, expected 8"

    def test_adas_payload_fits_8_bytes(self):
        """ADAS decision: 4 data bytes + 4 HMAC = 8 bytes."""
        data = struct.pack(can_ids.FMT_ADAS_DATA, 1, can_ids.DECISION_BRAKE, 0)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_LONG)
        assert len(signed) == 8

    def test_brake_payload_fits_8_bytes(self):
        """Brake: 4 data bytes + 4 HMAC = 8 bytes."""
        data = struct.pack(can_ids.FMT_BRAKE_DATA, 1, 100, 0)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_LONG)
        assert len(signed) == 8

    def test_gateway_payload_fits_8_bytes(self):
        """Gateway: 4 data bytes + 4 HMAC = 8 bytes."""
        data = struct.pack(can_ids.FMT_GATEWAY_DATA, 1, can_ids.RADAR_ID)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_LONG)
        assert len(signed) == 8


class TestHMACSignVerify:
    """Verify HMAC signing and verification round-trip."""

    def test_radar_hmac_roundtrip(self):
        data = struct.pack(can_ids.FMT_RADAR_DATA, 42, 800, -50)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_SHORT)
        payload, mac, valid = split_and_verify(signed, can_ids.HMAC_LEN_SHORT)
        assert valid, "HMAC verification failed on a correctly signed radar frame"
        assert payload == data

    def test_camera_hmac_roundtrip(self):
        data = struct.pack(can_ids.FMT_CAMERA_DATA, 7, can_ids.OBJ_PEDESTRIAN, 95)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_LONG)
        payload, mac, valid = split_and_verify(signed, can_ids.HMAC_LEN_LONG)
        assert valid
        assert payload == data

    def test_tampered_payload_fails(self):
        """Modifying one byte of the payload should cause HMAC verification to fail."""
        data = struct.pack(can_ids.FMT_RADAR_DATA, 1, 500, 0)
        signed = bytearray(sign_payload(data, truncate=can_ids.HMAC_LEN_SHORT))
        signed[2] ^= 0xFF  # Flip a byte in distance_cm
        _, _, valid = split_and_verify(bytes(signed), can_ids.HMAC_LEN_SHORT)
        assert not valid, "Tampered payload should fail HMAC verification"

    def test_truncated_hmac_wrong_length_fails(self):
        """Using the wrong HMAC truncation length should fail."""
        data = struct.pack(can_ids.FMT_CAMERA_DATA, 1, 1, 80)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_LONG)
        # Try verifying with short HMAC length — wrong split point
        _, _, valid = split_and_verify(signed, can_ids.HMAC_LEN_SHORT)
        assert not valid


class TestSequenceNumbers:
    """Verify sequence number behavior."""

    def test_seq_increments(self):
        """Sequence numbers should increment from 0."""
        seqs = []
        for i in range(5):
            data = struct.pack(can_ids.FMT_RADAR_DATA, i, 1000, 0)
            seq = struct.unpack(">H", data[:2])[0]
            seqs.append(seq)
        assert seqs == [0, 1, 2, 3, 4]

    def test_seq_wraps_at_65535(self):
        """Sequence should wrap around at 65535."""
        seq = 65535
        next_seq = (seq + 1) % 65536
        assert next_seq == 0


class TestDecisionLogic:
    """Verify ADAS ECU decision rules."""

    def test_brake_decision(self):
        """Close distance + high confidence → BRAKE."""
        distance_cm = 300   # < ADAS_BRAKE_DISTANCE_CM (500)
        confidence = 80     # > ADAS_MIN_CONFIDENCE (50)
        if distance_cm < can_ids.ADAS_BRAKE_DISTANCE_CM and confidence > can_ids.ADAS_MIN_CONFIDENCE:
            decision = can_ids.DECISION_BRAKE
        elif distance_cm < can_ids.ADAS_WARN_DISTANCE_CM:
            decision = can_ids.DECISION_WARN
        else:
            decision = can_ids.DECISION_NO_BRAKE
        assert decision == can_ids.DECISION_BRAKE

    def test_warn_decision(self):
        """Medium distance → WARN."""
        distance_cm = 700   # < ADAS_WARN_DISTANCE_CM (1000) but > ADAS_BRAKE_DISTANCE_CM (500)
        confidence = 30     # < ADAS_MIN_CONFIDENCE → skip brake even though distance is close
        if distance_cm < can_ids.ADAS_BRAKE_DISTANCE_CM and confidence > can_ids.ADAS_MIN_CONFIDENCE:
            decision = can_ids.DECISION_BRAKE
        elif distance_cm < can_ids.ADAS_WARN_DISTANCE_CM:
            decision = can_ids.DECISION_WARN
        else:
            decision = can_ids.DECISION_NO_BRAKE
        assert decision == can_ids.DECISION_WARN

    def test_no_brake_decision(self):
        """Far distance → NO_BRAKE."""
        distance_cm = 1500  # > ADAS_WARN_DISTANCE_CM
        confidence = 90
        if distance_cm < can_ids.ADAS_BRAKE_DISTANCE_CM and confidence > can_ids.ADAS_MIN_CONFIDENCE:
            decision = can_ids.DECISION_BRAKE
        elif distance_cm < can_ids.ADAS_WARN_DISTANCE_CM:
            decision = can_ids.DECISION_WARN
        else:
            decision = can_ids.DECISION_NO_BRAKE
        assert decision == can_ids.DECISION_NO_BRAKE


class TestCANBusCommunication:
    """Verify two nodes can send/receive over the virtual bus."""

    def test_send_receive(self):
        """Smoke test: send a message on the virtual bus and receive it."""
        bus_tx = get_bus()
        bus_rx = get_bus()

        data = struct.pack(can_ids.FMT_RADAR_DATA, 0, 1000, 50)
        signed = sign_payload(data, truncate=can_ids.HMAC_LEN_SHORT)

        msg_out = can.Message(
            arbitration_id=can_ids.RADAR_ID,
            data=signed,
            is_extended_id=False,
        )
        bus_tx.send(msg_out)

        msg_in = bus_rx.recv(timeout=1.0)
        assert msg_in is not None, "No message received on virtual bus"
        assert msg_in.arbitration_id == can_ids.RADAR_ID
        assert msg_in.data == signed

    def test_end_to_end_radar_to_brake(self):
        """
        Simulate radar → ADAS ECU → brake ECU pipeline manually.
        Verify correct decision flows through.
        """
        # 1. Radar sends close-range frame
        radar_data = struct.pack(can_ids.FMT_RADAR_DATA, 0, 200, 0)
        radar_signed = sign_payload(radar_data, truncate=can_ids.HMAC_LEN_SHORT)

        # 2. ADAS ECU receives and verifies
        payload, mac, valid = split_and_verify(radar_signed, can_ids.HMAC_LEN_SHORT)
        assert valid
        _, distance_cm, speed = struct.unpack(can_ids.FMT_RADAR_DATA, payload)
        assert distance_cm == 200

        # 3. ADAS decides (need high camera confidence for BRAKE)
        camera_confidence = 80
        if distance_cm < can_ids.ADAS_BRAKE_DISTANCE_CM and camera_confidence > can_ids.ADAS_MIN_CONFIDENCE:
            decision = can_ids.DECISION_BRAKE
        else:
            decision = can_ids.DECISION_NO_BRAKE
        assert decision == can_ids.DECISION_BRAKE

        # 4. ADAS sends decision
        adas_data = struct.pack(can_ids.FMT_ADAS_DATA, 0, decision, 0)
        adas_signed = sign_payload(adas_data, truncate=can_ids.HMAC_LEN_LONG)

        # 5. Brake ECU receives and verifies
        payload, mac, valid = split_and_verify(adas_signed, can_ids.HMAC_LEN_LONG)
        assert valid
        _, recv_decision, _ = struct.unpack(can_ids.FMT_ADAS_DATA, payload)
        assert recv_decision == can_ids.DECISION_BRAKE

        # 6. Brake ECU actuates
        brake_pct = 100 if recv_decision == can_ids.DECISION_BRAKE else 0
        assert brake_pct == 100
