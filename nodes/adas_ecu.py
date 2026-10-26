import sys
import os
import time
import struct
import logging
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import can_ids
from common import bus
from defense import crypto_utils
from can import Message

logger = logging.getLogger("adas_ecu")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

def run(stop_event, msg_callback=None):
    b = bus.get_bus()
    seq = 0
    
    last_distance_cm = can_ids.RADAR_DIST_MAX_CM
    last_camera_confidence = 0
    
    logger.info("ADAS ECU node started.")
    
    while not stop_event.is_set():
        msg = b.recv(timeout=0.1)
        if msg is None:
            continue
            
        received_valid = False
        
        if msg.arbitration_id == can_ids.RADAR_ID:
            payload, mac, valid = crypto_utils.split_and_verify(msg.data, can_ids.HMAC_LEN_SHORT)
            if valid:
                radar_seq, distance_cm, speed = struct.unpack(can_ids.FMT_RADAR_DATA, payload)
                last_distance_cm = distance_cm
                received_valid = True
                if msg_callback:
                    msg_callback({
                        'node': can_ids.NODE_ADAS,
                        'can_id': msg.arbitration_id,
                        'seq': radar_seq,
                        'data_dict': {'distance_cm': distance_cm, 'speed': speed, 'valid': valid},
                        'timestamp': time.time(),
                        'raw_bytes': msg.data
                    })
            else:
                logger.warning("Invalid HMAC on RADAR frame")
                
        elif msg.arbitration_id == can_ids.CAMERA_ID:
            payload, mac, valid = crypto_utils.split_and_verify(msg.data, can_ids.HMAC_LEN_LONG)
            if valid:
                cam_seq, obj_class, confidence = struct.unpack(can_ids.FMT_CAMERA_DATA, payload)
                last_camera_confidence = confidence if obj_class != can_ids.OBJ_NONE else 0
                received_valid = True
                if msg_callback:
                    msg_callback({
                        'node': can_ids.NODE_ADAS,
                        'can_id': msg.arbitration_id,
                        'seq': cam_seq,
                        'data_dict': {'obj_class': obj_class, 'confidence': confidence, 'valid': valid},
                        'timestamp': time.time(),
                        'raw_bytes': msg.data
                    })
            else:
                logger.warning("Invalid HMAC on CAMERA frame")
                
        if not received_valid:
            continue
            
        # Make a decision based on latest data
        if last_distance_cm < can_ids.ADAS_BRAKE_DISTANCE_CM and last_camera_confidence > can_ids.ADAS_MIN_CONFIDENCE:
            decision = can_ids.DECISION_BRAKE
        elif last_distance_cm < can_ids.ADAS_WARN_DISTANCE_CM:
            decision = can_ids.DECISION_WARN
        else:
            decision = can_ids.DECISION_NO_BRAKE
            
        # Send decision on 0x200
        # decision(1B) + pad(1B)
        payload = struct.pack(can_ids.FMT_ADAS_DATA, seq, decision, 0)
        signed_payload = crypto_utils.sign_payload(payload, truncate=can_ids.HMAC_LEN_LONG)
        
        out_msg = Message(arbitration_id=can_ids.ADAS_ID, data=signed_payload, is_extended_id=False)
        try:
            b.send(out_msg)
        except Exception as e:
            logger.error(f"Failed to send ADAS decision: {e}")
            
        if msg_callback:
            msg_callback({
                'node': can_ids.NODE_ADAS,
                'can_id': can_ids.ADAS_ID,
                'seq': seq,
                'data_dict': {'decision': decision},
                'timestamp': time.time(),
                'raw_bytes': signed_payload
            })
            
        seq = (seq + 1) % 65536
        
if __name__ == '__main__':
    stop_event = threading.Event()
    try:
        run(stop_event)
    except KeyboardInterrupt:
        logger.info("Stopping ADAS ECU node.")
        stop_event.set()
