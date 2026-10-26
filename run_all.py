#!/usr/bin/env python
"""
run_all.py — Single entry point for the ADAS Network Security project.

Starts all 5 ADAS nodes as threads, initializes the SQLite database,
and launches the Flask dashboard on http://localhost:5000.

Usage:
    python run_all.py              # Start everything (dashboard + nodes)
    python run_all.py --no-web     # Start nodes only (no dashboard)
    python run_all.py --port 8080  # Custom port

Press Ctrl+C for graceful shutdown.
"""

import os
import sys
import time
import signal
import logging
import argparse
import threading

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from common.can_ids import (
    NODE_RADAR, NODE_CAMERA, NODE_ADAS, NODE_GATEWAY, NODE_BRAKE
)
from common.bus import get_bus
from nodes.radar import run as run_radar
from nodes.camera import run as run_camera
from nodes.adas_ecu import run as run_adas
from nodes.brake_ecu import run as run_brake
from nodes.gateway import run as run_gateway

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("run_all")


def main():
    parser = argparse.ArgumentParser(description="ADAS Network Security — Run All")
    parser.add_argument("--no-web", action="store_true", help="Start nodes only, no dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Dashboard port (default: 5000)")
    args = parser.parse_args()

    stop_event = threading.Event()

    # ── Graceful shutdown ──
    def shutdown(signum=None, frame=None):
        logger.info("Shutting down all nodes...")
        stop_event.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if args.no_web:
        # ── Console-only mode: start nodes without dashboard ──
        logger.info("=" * 60)
        logger.info("ADAS Network Security — Console Mode")
        logger.info("=" * 60)

        threads = [
            threading.Thread(target=run_radar,   args=(stop_event,), daemon=True, name="radar"),
            threading.Thread(target=run_camera,  args=(stop_event,), daemon=True, name="camera"),
            threading.Thread(target=run_adas,    args=(stop_event,), daemon=True, name="adas_ecu"),
            threading.Thread(target=run_brake,   args=(stop_event,), daemon=True, name="brake_ecu"),
            threading.Thread(target=run_gateway, args=(stop_event,), daemon=True, name="gateway"),
        ]

        for t in threads:
            t.start()
            logger.info(f"  ✓ Started {t.name}")

        logger.info("-" * 60)
        logger.info("All nodes running. Press Ctrl+C to stop.")
        logger.info("-" * 60)

        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

        stop_event.set()
        for t in threads:
            t.join(timeout=3.0)

        logger.info("All nodes stopped. Goodbye!")

    else:
        # ── Dashboard mode: start Flask + SocketIO with nodes ──
        logger.info("=" * 60)
        logger.info("ADAS Network Security — Dashboard Mode")
        logger.info(f"  → http://localhost:{args.port}")
        logger.info("=" * 60)

        # Import here to avoid eventlet monkey-patching in console mode
        import eventlet
        eventlet.monkey_patch()

        from backend.app import app, socketio, start_nodes
        start_nodes()
        socketio.run(app, host='0.0.0.0', port=args.port, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()
