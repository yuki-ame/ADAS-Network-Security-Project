"""
test_attacks.py — Verify that each attack mode causes visible damage
when defenses are OFF.

These tests simulate attacks and confirm:
  - Spoof: ADAS ECU processes a forged radar frame (no HMAC check when defense is off)
  - Replay: A replayed frame is accepted a second time (stale seq not caught)
  - Flood: High-volume junk frames can be sent at the target rate
"""

import os
import sys
import struct
import time
import random
import threading
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import can_ids
from common.bus import get_bus
from defense.crypto_utils import sign_payload, split_and_verify
import can


class TestSpoofAttack:
    """Spoof attack: crafted frame with invalid HMAC on radar CAN ID."""

    def test_spoofed_frame_has_invalid_hmac(self):
        """A spoofed frame should fail HMAC verification."""
        # Attacker crafts a radar frame with distance=200 (close!) but random HMAC
        payload = struct.pack(can_ids.FMT_RADAR_DATA, 0, 200, 0)
        fake_hmac = bytes([random.randint(0, 255) for _ in range(can_ids.HMAC_LEN_SHORT)])
        spoofed_data = payload + fake_hmac

        # Verify that the HMAC is invalid
        _, _, valid = split_and_verify(spoofed_data, can_ids.HMAC_LEN_SHORT)
        assert not valid, "Spoofed frame should have invalid HMAC"

    def test_spoofed_frame_causes_phantom_brake_without_defense(self):
        """
        Without HMAC checking (defense off), the ADAS ECU would process
        the spoofed distance=200 and issue a BRAKE decision.
        """
        # Simulate what happens when ADAS ECU does NOT verify HMAC
        spoofed_payload = struct.pack(can_ids.FMT_RADAR_DATA, 0, 200, 0)
        # No HMAC check — just unpack the data
        seq, distance_cm, speed = struct.unpack(can_ids.FMT_RADAR_DATA, spoofed_payload)

        assert distance_cm == 200
        assert distance_cm < can_ids.ADAS_BRAKE_DISTANCE_CM

        # ECU makes a brake decision on this fake data
        camera_confidence = 80  # Assuming camera also reports high confidence
        if distance_cm < can_ids.ADAS_BRAKE_DISTANCE_CM and camera_confidence > can_ids.ADAS_MIN_CONFIDENCE:
            decision = can_ids.DECISION_BRAKE
        else:
            decision = can_ids.DECISION_NO_BRAKE

        assert decision == can_ids.DECISION_BRAKE, \
            "Spoofed close-range data should cause phantom braking without defense"

    def test_spoofed_frame_on_bus(self):
        """Send a spoofed frame on the bus and confirm it's receivable."""
        bus_tx = get_bus()
        bus_rx = get_bus()

        payload = struct.pack(can_ids.FMT_RADAR_DATA, 0, 200, 0)
        fake_hmac = bytes([0xDE, 0xAD])
        spoofed_data = payload + fake_hmac

        msg = can.Message(
            arbitration_id=can_ids.RADAR_ID,
            data=spoofed_data,
            is_extended_id=False,
        )
        bus_tx.send(msg)

        received = bus_rx.recv(timeout=1.0)
        assert received is not None
        assert received.arbitration_id == can_ids.RADAR_ID
        assert received.data == spoofed_data


class TestReplayAttack:
    """Replay attack: re-send a legitimate frame after a delay."""

    def test_replay_uses_same_data(self):
        """A replayed frame is bit-for-bit identical to the captured one."""
        # Create a legitimate frame
        payload = struct.pack(can_ids.FMT_RADAR_DATA, 42, 800, -30)
        signed = sign_payload(payload, truncate=can_ids.HMAC_LEN_SHORT)

        # "Capture" it
        captured = bytes(signed)

        # "Replay" it — exact same data
        assert captured == signed, "Replayed data should be identical to captured"

        # HMAC is still valid (that's the point — it was a real frame)
        _, _, valid = split_and_verify(captured, can_ids.HMAC_LEN_SHORT)
        assert valid, "Replayed frame should have a valid HMAC (it's a copy of a real one)"

    def test_replay_has_stale_sequence(self):
        """
        A replayed frame has the same seq as the original.
        Without seq tracking, the ECU would process it again.
        """
        # First frame: seq=10
        payload_1 = struct.pack(can_ids.FMT_RADAR_DATA, 10, 500, 0)
        signed_1 = sign_payload(payload_1, truncate=can_ids.HMAC_LEN_SHORT)

        # Next legitimate frame: seq=11
        payload_2 = struct.pack(can_ids.FMT_RADAR_DATA, 11, 600, 0)
        signed_2 = sign_payload(payload_2, truncate=can_ids.HMAC_LEN_SHORT)

        # Replay of first frame: seq=10 (stale!)
        replayed = bytes(signed_1)
        replay_payload, _, _ = split_and_verify(replayed, can_ids.HMAC_LEN_SHORT)
        replay_seq = struct.unpack(">H", replay_payload[:2])[0]

        assert replay_seq == 10, "Replayed frame should have stale seq=10"
        assert replay_seq < 11, "Replayed seq should be less than current expected seq"

    def test_replay_on_bus(self):
        """Send, capture, and replay a frame on the virtual bus."""
        bus_a = get_bus()
        bus_b = get_bus()

        # Original frame
        payload = struct.pack(can_ids.FMT_RADAR_DATA, 5, 1000, 50)
        signed = sign_payload(payload, truncate=can_ids.HMAC_LEN_SHORT)
        msg = can.Message(arbitration_id=can_ids.RADAR_ID, data=signed, is_extended_id=False)

        bus_a.send(msg)
        captured = bus_b.recv(timeout=1.0)
        assert captured is not None

        # Replay: send the exact same bytes again
        replay_msg = can.Message(
            arbitration_id=captured.arbitration_id,
            data=captured.data,
            is_extended_id=False,
        )
        bus_a.send(replay_msg)
        replayed = bus_b.recv(timeout=1.0)

        assert replayed is not None
        assert replayed.data == captured.data, "Replayed frame should be identical"


class TestFloodAttack:
    """Flood attack: high-rate junk frames on the bus."""

    def test_flood_generates_junk_frames(self):
        """Flood frames should have random CAN IDs in the 0x400–0x7FE range."""
        for _ in range(100):
            can_id = random.randint(0x400, 0x7FE)
            data = bytes([random.randint(0, 255) for _ in range(8)])
            assert 0x400 <= can_id <= 0x7FE
            assert len(data) == 8

    def test_flood_avoids_known_ids(self):
        """Flood traffic should NOT use legitimate CAN IDs."""
        for _ in range(1000):
            can_id = random.randint(0x400, 0x7FE)
            assert can_id not in can_ids.ALL_KNOWN_IDS, \
                f"Flood frame used known CAN ID 0x{can_id:03X}"

    def test_flood_rate_measurement(self):
        """Verify we can send frames at high rate on the virtual bus."""
        bus_tx = get_bus()
        target_count = 500
        start = time.time()

        for i in range(target_count):
            can_id = random.randint(0x400, 0x7FE)
            data = bytes([random.randint(0, 255) for _ in range(8)])
            msg = can.Message(arbitration_id=can_id, data=data, is_extended_id=False)
            bus_tx.send(msg)

        elapsed = time.time() - start
        rate = target_count / elapsed if elapsed > 0 else float('inf')
        # Virtual bus should handle at least 500 frames in under 5 seconds
        assert elapsed < 5.0, f"Sending {target_count} frames took {elapsed:.2f}s (too slow)"
