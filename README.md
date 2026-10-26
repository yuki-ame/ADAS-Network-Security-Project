# ADAS Network Security — Simulation Framework

> **Network Security for Advanced Driver Assistance Systems (ADAS)**
> A Simulation-Based Attack & Defense Framework for Automotive CAN Networks

**Team K003/K006/K014/K064** · NMIMS MPSTME Mumbai · B.Tech CSE (Cybersecurity) 2025-26

---

## Overview

This project simulates a complete ADAS communication pipeline over a virtual CAN bus, then demonstrates three attack vectors (spoofing, replay, flooding) and a multi-layered Intrusion Detection System (IDS) that detects and blocks them in real time.

### Architecture

```
┌─────────┐    ┌─────────┐
│  Radar  │    │ Camera  │       Sensor Layer
│  0x100  │    │  0x101  │
└────┬────┘    └────┬────┘
     │              │
     ▼              ▼
┌────────────────────────┐
│    Virtual CAN Bus     │◄──── Attacker (spoof/replay/flood)
└────────────┬───────────┘
             │
     ┌───────┼───────┐
     ▼       ▼       ▼
┌─────────┐ ┌───────┐ ┌──────────┐
│ADAS ECU │ │Gateway│ │ IDS      │  Processing + Security
│  0x200  │ │ 0x201 │ │ 4 layers │
└────┬────┘ └───┬───┘ └──────────┘
     │          │
     ▼          ▼
┌─────────┐ ┌──────────────────┐
│Brake ECU│ │ Flask Dashboard  │  Actuation + Monitoring
│  0x300  │ │ + SQLite + WS    │
└─────────┘ └──────────────────┘
```

### IDS Defense Layers

| Layer | Check | Catches |
|-------|-------|---------|
| 1 | HMAC-SHA256 verification | Spoofing |
| 2 | Sequence number tracking | Replay |
| 3 | Sliding-window rate limiting | Flooding |
| 4 | Node isolation (blocklist) | Repeat offenders |

---

## Quick Start

### 1. Setup

```bash
# Clone and enter the project
cd adas-network-security

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Dashboard

```bash
python run_all.py
```

Open **http://localhost:5000** in your browser.

The dashboard opens with CAN messages stopped. Click **Start Messages** to start the
five ADAS nodes, and **Stop Messages** to stop them and any running attack. The web
dashboard stays available, and messages can be started again without restarting Python.

### 3. Run Without Dashboard (Console Only)

```bash
python run_all.py --no-web
```

### 4. Run Tests

```bash
python -m pytest tests/ -v
```

### 5. Run Individual Attacks (CLI)

```bash
python attacker/attacker.py --mode spoof --duration 10
python attacker/attacker.py --mode replay --duration 10
python attacker/attacker.py --mode flood --rate 5000 --duration 10
```

---

## Project Structure

```
adas-network-security/
├── common/
│   ├── can_ids.py          # CAN ID constants, payload formats, shared key
│   └── bus.py              # Virtual CAN bus helper
├── nodes/
│   ├── radar.py            # Synthetic radar sensor (0x100)
│   ├── camera.py           # Synthetic camera sensor (0x101)
│   ├── adas_ecu.py         # Decision logic: brake/warn/no-brake (0x200)
│   ├── brake_ecu.py        # Actuation: brake percentage (0x300)
│   └── gateway.py          # Relay/log all traffic (0x201)
├── attacker/
│   └── attacker.py         # Spoof, replay, flood attack modes
├── defense/
│   ├── ids.py              # 4-layer Intrusion Detection System
│   └── crypto_utils.py     # HMAC-SHA256 sign/verify helpers
├── backend/
│   ├── app.py              # Flask + SocketIO server
│   ├── db.py               # SQLite helpers
│   └── models.sql          # Database schema
├── frontend/
│   ├── templates/
│   │   └── dashboard.html  # Dashboard page
│   └── static/
│       ├── dashboard.js    # Chart.js + SocketIO client
│       └── style.css       # Dark automotive theme
├── tests/
│   ├── test_normal_traffic.py
│   ├── test_attacks.py
│   └── test_defenses.py
├── results/                # Exported CSVs for the report
├── requirements.txt
├── run_all.py              # Single entry point
└── README.md
```

---

## CAN Message Formats

All CAN data frames are exactly **8 bytes** (standard CAN constraint).

| CAN ID | Node | Format | HMAC |
|--------|------|--------|------|
| `0x100` | Radar | seq(2B) + distance_cm(2B) + speed_x10(2B) + hmac(2B) | 2B |
| `0x101` | Camera | seq(2B) + obj_class(1B) + confidence(1B) + hmac(4B) | 4B |
| `0x200` | ADAS ECU | seq(2B) + decision(1B) + pad(1B) + hmac(4B) | 4B |
| `0x201` | Gateway | seq(2B) + origin_id(2B) + hmac(4B) | 4B |
| `0x300` | Brake ECU | seq(2B) + brake_pct(1B) + pad(1B) + hmac(4B) | 4B |

> **Note**: Radar uses only 2-byte HMAC due to its 6-byte data payload. This trade-off is documented as a real-world CAN constraint.

---

## Dashboard Controls

| Control | Action |
|---------|--------|
| **Start Messages** | Start the five ADAS nodes and CAN message transmission |
| **Stop Messages** | Stop all nodes and any running attack; keep the dashboard open |
| **Attack Mode** dropdown | Select: Spoof / Replay / Flood |
| **Rate** input | Frames/sec for flood mode |
| **Launch Attack** | Start the selected attack |
| **Stop Attack** | Stop the running attack |
| **IDS Defense** toggle | Enable/disable the 4-layer IDS |

---

## Testing Matrix

Run each attack with defenses OFF then ON:

| Scenario | Expected Result |
|----------|----------------|
| Spoof + Defense OFF | Phantom brake decision |
| Spoof + Defense ON | HMAC check blocks → alert logged |
| Replay + Defense OFF | Stale data reprocessed |
| Replay + Defense ON | Seq check blocks → alert logged |
| Flood + Defense OFF | Bus saturation, delayed frames |
| Flood + Defense ON | Rate limiter throttles → alert logged |

---

## License

Academic project — NMIMS MPSTME Mumbai, 2025-26.
