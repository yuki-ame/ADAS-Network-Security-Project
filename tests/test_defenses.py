"""
test_defenses.py — Verify that the IDS catches all three attack types.

Tests each IDS layer independently with crafted bad frames:
  1. HMAC verification → catches spoofing
  2. Sequence check → catches replay
  3. Rate limiting → catches flooding
  4. Node isolation → blocks repeat offenders

Also verifies zero false positives on legitimate traffic.
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
from defense.crypto_utils import sign_payload
from defense.ids import IntrusionDetectionSystem
import can


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def make_legitimate_radar_frame(seq, distance_cm=1000, speed=0):
    """Create a properly signed radar CAN message."""
    payload = struct.pack(can_ids.FMT_RADAR_DATA, seq, distance_cm, speed)
    signed = sign_payload(payload, truncate=can_ids.HMAC_LEN_SHORT)
    return can.Message(arbitration_id=can_ids.RADAR_ID, data=signed, is_extended_id=False)


def make_legitimate_camera_frame(seq, obj_class=1, confidence=80):
    """Create a properly signed camera CAN message."""
    payload = struct.pack(can_ids.FMT_CAMERA_DATA, seq, obj_class, confidence)
    signed = sign_payload(payload, truncate=can_ids.HMAC_LEN_LONG)
    return can.Message(arbitration_id=can_ids.CAMERA_ID, data=signed, is_extended_id=False)


def make_spoofed_radar_frame(seq=0, distance_cm=200):
    """Create a radar frame with INVALID HMAC (spoofed)."""
    payload = struct.pack(can_ids.FMT_RADAR_DATA, seq, distance_cm, 0)
    fake_hmac = bytes([random.randint(0, 255) for _ in range(can_ids.HMAC_LEN_SHORT)])
    data = payload + fake_hmac
    return can.Message(arbitration_id=can_ids.RADAR_ID, data=data, is_extended_id=False)


# ──────────────────────────────────────────────
# Layer 1: HMAC Verification (anti-spoof)
# ──────────────────────────────────────────────

class TestHMACVerification:
    """IDS should reject frames with invalid HMACs."""

    def test_valid_hmac_passes(self):
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))
        msg = make_legitimate_radar_frame(seq=0)
        assert ids.inspect_frame(msg) is True
        assert len(alerts) == 0

    def test_invalid_hmac_blocked(self):
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))
        msg = make_spoofed_radar_frame(seq=0)
        assert ids.inspect_frame(msg) is False
        assert len(alerts) == 1
        assert alerts[0]['alert_type'] == 'spoof'
        assert alerts[0]['action_taken'] == 'blocked'

    def test_multiple_spoofs_all_blocked(self):
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))
        for i in range(4):
            msg = make_spoofed_radar_frame(seq=i)
            assert ids.inspect_frame(msg) is False
        assert len(alerts) == 4
        assert all(a['alert_type'] == 'spoof' for a in alerts)


# ──────────────────────────────────────────────
# Layer 2: Sequence Check (anti-replay)
# ──────────────────────────────────────────────

class TestSequenceCheck:
    """IDS should reject frames with stale/repeated sequence numbers."""

    def test_incrementing_seq_passes(self):
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))
        for seq in range(5):
            msg = make_legitimate_radar_frame(seq=seq)
            assert ids.inspect_frame(msg) is True
        assert len(alerts) == 0

    def test_repeated_seq_blocked(self):
        """Replaying a frame with the same seq should be blocked."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        # First: seq=5 passes
        msg1 = make_legitimate_radar_frame(seq=5)
        assert ids.inspect_frame(msg1) is True

        # Replay: seq=5 again → blocked
        msg2 = make_legitimate_radar_frame(seq=5)
        assert ids.inspect_frame(msg2) is False
        assert len(alerts) == 1
        assert alerts[0]['alert_type'] == 'replay'

    def test_older_seq_blocked(self):
        """A frame with seq < last_seen should be blocked as replay."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        # Send seq 0, 1, 2
        for seq in range(3):
            ids.inspect_frame(make_legitimate_radar_frame(seq=seq))

        # Try seq=1 (stale) → blocked
        msg = make_legitimate_radar_frame(seq=1)
        assert ids.inspect_frame(msg) is False
        assert alerts[-1]['alert_type'] == 'replay'

    def test_different_nodes_have_independent_seq(self):
        """Each (node, can_id) pair tracks seq independently."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        # Radar seq=0, Camera seq=0 — both should pass (different nodes)
        assert ids.inspect_frame(make_legitimate_radar_frame(seq=0)) is True
        assert ids.inspect_frame(make_legitimate_camera_frame(seq=0)) is True
        assert len(alerts) == 0


# ──────────────────────────────────────────────
# Layer 3: Rate Limiting (anti-flood)
# ──────────────────────────────────────────────

class TestRateLimiting:
    """IDS should throttle nodes exceeding the rate limit."""

    def test_normal_rate_passes(self):
        """Sending below the rate limit should not trigger alerts."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        # Send 10 legitimate frames (well under 200/sec limit)
        for seq in range(10):
            msg = make_legitimate_radar_frame(seq=seq)
            ids.inspect_frame(msg)

        # Filter for flood alerts only
        flood_alerts = [a for a in alerts if a['alert_type'] == 'flood']
        assert len(flood_alerts) == 0

    def test_excessive_rate_blocked(self):
        """Sending more than RATE_LIMIT_MSG_PER_SEC in one window should trigger rate limiting."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        # Send rate_limit + 10 frames as fast as possible
        limit = can_ids.RATE_LIMIT_MSG_PER_SEC
        blocked_count = 0
        for seq in range(limit + 10):
            msg = make_legitimate_radar_frame(seq=seq)
            result = ids.inspect_frame(msg)
            if not result:
                blocked_count += 1

        flood_alerts = [a for a in alerts if a['alert_type'] == 'flood']
        assert len(flood_alerts) > 0, "Should have triggered at least one flood alert"
        assert blocked_count > 0, "Some frames should have been blocked"

    def test_flood_from_unknown_ids(self):
        """Junk CAN IDs (0x400+) should be blocked as unknown."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        junk_msg = can.Message(
            arbitration_id=0x500,
            data=bytes(8),
            is_extended_id=False,
        )
        # These should hit rate limit or unknown-ID check
        for _ in range(5):
            ids.inspect_frame(junk_msg)

        assert len(alerts) > 0


# ──────────────────────────────────────────────
# Layer 4: Node Isolation
# ──────────────────────────────────────────────

class TestNodeIsolation:
    """IDS should isolate nodes after reaching the alert threshold."""

    def test_node_isolated_after_threshold(self):
        """After NODE_ISOLATION_THRESHOLD alerts, the node should be blocklisted."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        threshold = can_ids.NODE_ISOLATION_THRESHOLD

        # Send spoofed frames to exceed threshold
        for i in range(threshold + 2):
            msg = make_spoofed_radar_frame(seq=i)
            ids.inspect_frame(msg)

        # Check that node is isolated
        status = ids.get_node_status(can_ids.NODE_RADAR)
        assert status['status'] == 'isolated', \
            f"Node should be isolated after {threshold} alerts, got status: {status['status']}"

    def test_isolated_node_frames_dropped(self):
        """Once isolated, even valid frames from the node should be dropped."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        threshold = can_ids.NODE_ISOLATION_THRESHOLD

        # Trigger isolation with spoofed frames
        for i in range(threshold + 1):
            ids.inspect_frame(make_spoofed_radar_frame(seq=i))

        # Now send a VALID radar frame — should still be blocked
        valid_msg = make_legitimate_radar_frame(seq=100)
        result = ids.inspect_frame(valid_msg)
        assert result is False, "Valid frame from isolated node should be dropped"

    def test_reset_node_removes_isolation(self):
        """reset_node() should un-isolate and clear alert count."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        # Isolate the radar node
        for i in range(can_ids.NODE_ISOLATION_THRESHOLD + 1):
            ids.inspect_frame(make_spoofed_radar_frame(seq=i))

        assert ids.get_node_status(can_ids.NODE_RADAR)['status'] == 'isolated'

        # Reset
        ids.reset_node(can_ids.NODE_RADAR)
        status = ids.get_node_status(can_ids.NODE_RADAR)
        assert status['status'] != 'isolated'
        assert status['alert_count'] == 0

        # Valid frame should pass again
        valid_msg = make_legitimate_radar_frame(seq=200)
        assert ids.inspect_frame(valid_msg) is True


# ──────────────────────────────────────────────
# False Positive Tests
# ──────────────────────────────────────────────

class TestFalsePositives:
    """Verify zero false positives on clean legitimate traffic."""

    def test_clean_traffic_no_alerts(self):
        """
        Send a stream of properly signed, sequenced frames from
        multiple nodes — no alerts should be generated.
        """
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))

        # Simulate 50 rounds of normal traffic
        for seq in range(50):
            ids.inspect_frame(make_legitimate_radar_frame(seq=seq))
            ids.inspect_frame(make_legitimate_camera_frame(seq=seq))

            # ADAS decision
            adas_data = struct.pack(can_ids.FMT_ADAS_DATA, seq, can_ids.DECISION_NO_BRAKE, 0)
            adas_signed = sign_payload(adas_data, truncate=can_ids.HMAC_LEN_LONG)
            adas_msg = can.Message(arbitration_id=can_ids.ADAS_ID, data=adas_signed, is_extended_id=False)
            ids.inspect_frame(adas_msg)

            # Brake confirmation
            brake_data = struct.pack(can_ids.FMT_BRAKE_DATA, seq, 0, 0)
            brake_signed = sign_payload(brake_data, truncate=can_ids.HMAC_LEN_LONG)
            brake_msg = can.Message(arbitration_id=can_ids.BRAKE_ID, data=brake_signed, is_extended_id=False)
            ids.inspect_frame(brake_msg)

            # Gateway summary
            gw_data = struct.pack(can_ids.FMT_GATEWAY_DATA, seq, can_ids.RADAR_ID)
            gw_signed = sign_payload(gw_data, truncate=can_ids.HMAC_LEN_LONG)
            gw_msg = can.Message(arbitration_id=can_ids.GATEWAY_ID, data=gw_signed, is_extended_id=False)
            ids.inspect_frame(gw_msg)

        assert len(alerts) == 0, \
            f"Expected 0 false positives on clean traffic, got {len(alerts)}: {alerts}"

    def test_ids_disabled_passes_everything(self):
        """When IDS is disabled, all frames should pass through."""
        alerts = []
        ids = IntrusionDetectionSystem(alert_callback=lambda a: alerts.append(a))
        ids.disable()

        # Even a spoofed frame should pass when IDS is disabled
        spoofed = make_spoofed_radar_frame(seq=0)
        assert ids.inspect_frame(spoofed) is True
        assert len(alerts) == 0
