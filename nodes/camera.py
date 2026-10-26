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

logger = logging.getLogger("camera")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

def run(stop_event, msg_callback=None):
    b = bus.get_bus()
    seq = 0
    
    logger.info("Camera node started.")
    
    while not stop_event.is_set():
        obj_class = random.choice([can_ids.OBJ_NONE, can_ids.OBJ_CAR, can_ids.OBJ_PEDESTRIAN, can_ids.OBJ_CYCLIST])
        if obj_class == can_ids.OBJ_NONE:
            confidence = 0
        else:
            # bias towards higher confidence
            confidence = random.randint(30, can_ids.CAMERA_CONFIDENCE_MAX)
            
        payload = struct.pack(can_ids.FMT_CAMERA_DATA, seq, obj_class, confidence)
        signed_payload = crypto_utils.sign_payload(payload, truncate=can_ids.HMAC_LEN_LONG)
        
        msg = Message(arbitration_id=can_ids.CAMERA_ID, data=signed_payload, is_extended_id=False)
        try:
            b.send(msg)
        except Exception as e:
            logger.error(f"Failed to send CAN message: {e}")
        
        if msg_callback:
            msg_callback({
                'node': can_ids.NODE_CAMERA,
                'can_id': can_ids.CAMERA_ID,
                'seq': seq,
                'data_dict': {'obj_class': obj_class, 'confidence': confidence},
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
        logger.info("Stopping camera node.")
        stop_event.set()
