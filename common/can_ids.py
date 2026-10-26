"""
can_ids.py — Shared CAN ID constants, payload formats, and configuration.

All nodes, the attacker, and the IDS import from here so message formats
stay consistent across the entire simulation.

CAN data frames carry at most 8 bytes.  HMAC is truncated to fit:
  - Radar (0x100):  6 data bytes + 2-byte HMAC  (tighter constraint)
  - All others:     4 data bytes + 4-byte HMAC
This trade-off is documented as a real-world CAN limitation.
"""

import struct

# ──────────────────────────────────────────────
# CAN Arbitration IDs
# ──────────────────────────────────────────────
RADAR_ID   = 0x100   # Radar sensor → ADAS ECU
CAMERA_ID  = 0x101   # Camera sensor → ADAS ECU
ADAS_ID    = 0x200   # ADAS ECU decision → Brake ECU
GATEWAY_ID = 0x201   # Gateway relay/log frame
BRAKE_ID   = 0x300   # Brake ECU actuation confirmation

# ──────────────────────────────────────────────
# Node names (used as keys in IDS tracking dicts)
# ──────────────────────────────────────────────
NODE_RADAR   = "radar"
NODE_CAMERA  = "camera"
NODE_ADAS    = "adas_ecu"
NODE_GATEWAY = "gateway"
NODE_BRAKE   = "brake_ecu"

# Map CAN ID → canonical node name (for IDS lookups)
CAN_ID_TO_NODE = {
    RADAR_ID:   NODE_RADAR,
    CAMERA_ID:  NODE_CAMERA,
    ADAS_ID:    NODE_ADAS,
    GATEWAY_ID: NODE_GATEWAY,
    BRAKE_ID:   NODE_BRAKE,
}

ALL_KNOWN_IDS = set(CAN_ID_TO_NODE.keys())

# ──────────────────────────────────────────────
# HMAC shared key (32 bytes)
# In a real vehicle this would come from a hardware security module.
# ──────────────────────────────────────────────
HMAC_KEY = bytes([
    0xAD, 0xA5, 0x5E, 0xC0, 0x01, 0x7E, 0xCA, 0xFE,
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10, 0xAD, 0xA5, 0x5E, 0xC0,
])

# ──────────────────────────────────────────────
# HMAC truncation lengths (bytes)
# ──────────────────────────────────────────────
HMAC_LEN_SHORT = 2   # Radar frames (tight on space)
HMAC_LEN_LONG  = 4   # All other frames

# Per-CAN-ID HMAC length
HMAC_LEN_BY_ID = {
    RADAR_ID:   HMAC_LEN_SHORT,
    CAMERA_ID:  HMAC_LEN_LONG,
    ADAS_ID:    HMAC_LEN_LONG,
    GATEWAY_ID: HMAC_LEN_LONG,
    BRAKE_ID:   HMAC_LEN_LONG,
}

# ──────────────────────────────────────────────
# Payload struct formats (big-endian '>')
#
# Radar  (0x100): seq(2B) + distance_cm(2B) + rel_speed_x10(2B) + hmac(2B)
# Camera (0x101): seq(2B) + obj_class(1B) + confidence(1B) + hmac(4B)
# ADAS   (0x200): seq(2B) + decision(1B) + pad(1B) + hmac(4B)
# Gateway(0x201): seq(2B) + origin_id(2B) + hmac(4B)
# Brake  (0x300): seq(2B) + brake_pct(1B) + pad(1B) + hmac(4B)
# ──────────────────────────────────────────────
FMT_RADAR_DATA   = ">HHh"      # seq, distance_cm, rel_speed_x10 → 6B
FMT_CAMERA_DATA  = ">HBB"      # seq, obj_class, confidence → 4B
FMT_ADAS_DATA    = ">HBB"      # seq, decision, pad → 4B
FMT_GATEWAY_DATA = ">HH"       # seq, origin_id → 4B
FMT_BRAKE_DATA   = ">HBB"      # seq, brake_pct, pad → 4B

# ──────────────────────────────────────────────
# Decision codes (ADAS ECU → Brake ECU)
# ──────────────────────────────────────────────
DECISION_NO_BRAKE = 0
DECISION_WARN     = 1
DECISION_BRAKE    = 2

DECISION_NAMES = {
    DECISION_NO_BRAKE: "NO_BRAKE",
    DECISION_WARN:     "WARN",
    DECISION_BRAKE:    "BRAKE",
}

# ──────────────────────────────────────────────
# Camera object classes
# ──────────────────────────────────────────────
OBJ_NONE       = 0
OBJ_CAR        = 1
OBJ_PEDESTRIAN = 2
OBJ_CYCLIST    = 3

OBJ_CLASS_NAMES = {
    OBJ_NONE:       "none",
    OBJ_CAR:        "car",
    OBJ_PEDESTRIAN: "pedestrian",
    OBJ_CYCLIST:    "cyclist",
}

# ──────────────────────────────────────────────
# IDS tuning thresholds
# ──────────────────────────────────────────────
RATE_LIMIT_MSG_PER_SEC = 200    # per-node rate limit
RATE_LIMIT_WINDOW_SEC  = 1.0    # sliding window size
NODE_ISOLATION_THRESHOLD = 5    # alert count before blocklist

# ──────────────────────────────────────────────
# Sensor data ranges (for synthetic generation)
# ──────────────────────────────────────────────
RADAR_DIST_MIN_CM  = 50
RADAR_DIST_MAX_CM  = 2000
RADAR_SPEED_MIN_X10 = -1000   # -100.0 km/h
RADAR_SPEED_MAX_X10 =  1000   # +100.0 km/h

CAMERA_CONFIDENCE_MIN = 0
CAMERA_CONFIDENCE_MAX = 100

# ──────────────────────────────────────────────
# ADAS decision thresholds
# ──────────────────────────────────────────────
ADAS_BRAKE_DISTANCE_CM    = 500    # distance < this → BRAKE
ADAS_WARN_DISTANCE_CM     = 1000   # distance < this → WARN
ADAS_MIN_CONFIDENCE       = 50     # camera confidence must exceed this

# ──────────────────────────────────────────────
# Timing
# ──────────────────────────────────────────────
SENSOR_INTERVAL_SEC = 0.1   # 100ms between sensor frames

# ──────────────────────────────────────────────
# Helper: get data length (bytes before HMAC) for a CAN ID
# ──────────────────────────────────────────────
DATA_LEN_BY_ID = {
    RADAR_ID:   struct.calcsize(FMT_RADAR_DATA),    # 6
    CAMERA_ID:  struct.calcsize(FMT_CAMERA_DATA),   # 4
    ADAS_ID:    struct.calcsize(FMT_ADAS_DATA),      # 4
    GATEWAY_ID: struct.calcsize(FMT_GATEWAY_DATA),   # 4
    BRAKE_ID:   struct.calcsize(FMT_BRAKE_DATA),     # 4
}
