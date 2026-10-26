"""
bus.py — Shared virtual CAN bus setup.

By default uses python-can's pure-Python 'virtual' bustype on channel 'adas',
which requires no OS-level setup and works on Windows/macOS/Linux.

To use Linux socketcan instead, set environment variables:
    export CAN_INTERFACE=socketcan
    export CAN_CHANNEL=vcan0
"""

import os
import threading
from contextlib import contextmanager
import can

# Defaults: pure-Python virtual bus (cross-platform)
DEFAULT_INTERFACE = "virtual"
DEFAULT_CHANNEL   = "adas"
_bus_scope = threading.local()


@contextmanager
def managed_buses():
    """Close every bus opened by this node thread when it stops or fails."""
    previous = getattr(_bus_scope, 'buses', None)
    _bus_scope.buses = []
    try:
        yield
    finally:
        for bus in _bus_scope.buses:
            bus.shutdown()
        _bus_scope.buses = previous


def get_bus(**kwargs) -> can.BusABC:
    """
    Create and return a CAN bus instance.

    Reads CAN_INTERFACE and CAN_CHANNEL from the environment, falling back
    to the virtual bus.  Extra kwargs are forwarded to can.interface.Bus().

    Returns:
        can.BusABC: A connected CAN bus instance.
    """
    interface = os.environ.get("CAN_INTERFACE", DEFAULT_INTERFACE)
    channel   = os.environ.get("CAN_CHANNEL", DEFAULT_CHANNEL)

    bus = can.interface.Bus(
        channel=channel,
        interface=interface,
        is_extended_id=False,
        **kwargs,
    )
    if getattr(_bus_scope, 'buses', None) is not None:
        _bus_scope.buses.append(bus)
    return bus
