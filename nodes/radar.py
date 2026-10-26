import sys
import os
import time
import struct
import logging
import threading
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import can_ids
from common import bus
from defense import crypto_utils
from can import Message

logger = logging.getLogger("radar")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

def run(stop_event, msg_callback=None):
    b = bus.get_bus()
    seq = 0
    
    distance_cm = can_ids.RADAR_DIST_MAX_CM
    direction = -100  # Change distance more quickly for synthetic data
    
    logger.info("Radar node started.")
    
    while not stop_event.is_set():
        # Update distance
        distance_cm += direction
        if distance_cm <= can_ids.RADAR_DIST_MIN_CM:
            distance_cm = can_ids.RADAR_DIST_MIN_CM
            direction = abs(direction)
        elif distance_cm >= can_ids.RADAR_DIST_MAX_CM:
            distance_cm = can_ids.RADAR_DIST_MAX_CM
            direction = -abs(direction)
            
        speed = random.randint(can_ids.RADAR_SPEED_MIN_X10, can_ids.RADAR_SPEED_MAX_X10)
        
        payload = struct.pack(can_ids.FMT_RADAR_DATA, seq, distance_cm, speed)
        signed_payload = crypto_utils.sign_payload(payload, truncate=can_ids.HMAC_LEN_SHORT)
        
        msg = Message(arbitration_id=can_ids.RADAR_ID, data=signed_payload, is_extended_id=False)
        try:
            b.send(msg)
        except Exception as e:
            logger.error(f"Failed to send CAN message: {e}")
        
        if msg_callback:
            msg_callback({
                'node': can_ids.NODE_RADAR,
                'can_id': can_ids.RADAR_ID,
                'seq': seq,
                'data_dict': {'distance_cm': distance_cm, 'speed': speed},
                'timestamp': time.time(),
                'raw_bytes': signed_payload
            })
            
        seq = (seq + 1) % 65536
        stop_event.wait(can_ids.SENSOR_INTERVAL_SEC)
        
if __name__ == '__main__':
    stop_event = threading.Event()
    try:
        run(stop_event)
    except KeyboardInterrupt:
        logger.info("Stopping radar node.")
        stop_event.set()
