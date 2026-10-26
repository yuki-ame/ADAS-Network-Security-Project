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

logger = logging.getLogger("brake_ecu")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

def run(stop_event, msg_callback=None):
    b = bus.get_bus()
    seq = 0
    
    logger.info("Brake ECU node started.")
    
    while not stop_event.is_set():
        msg = b.recv(timeout=0.1)
        if msg is None:
            continue
            
        if msg.arbitration_id == can_ids.ADAS_ID:
            payload, mac, valid = crypto_utils.split_and_verify(msg.data, can_ids.HMAC_LEN_LONG)
            if valid:
                adas_seq, decision, _ = struct.unpack(can_ids.FMT_ADAS_DATA, payload)
                
                if decision == can_ids.DECISION_BRAKE:
                    brake_pct = 100
                elif decision == can_ids.DECISION_WARN:
                    brake_pct = 30
                else:
                    brake_pct = 0
                    
                logger.info(f"Received decision {can_ids.DECISION_NAMES.get(decision, 'UNKNOWN')} - Actuating brake at {brake_pct}%")
                
                out_payload = struct.pack(can_ids.FMT_BRAKE_DATA, seq, brake_pct, 0)
                signed_payload = crypto_utils.sign_payload(out_payload, truncate=can_ids.HMAC_LEN_LONG)
                
                out_msg = Message(arbitration_id=can_ids.BRAKE_ID, data=signed_payload, is_extended_id=False)
                try:
                    b.send(out_msg)
                except Exception as e:
                    logger.error(f"Failed to send BRAKE confirmation: {e}")
                    
                if msg_callback:
                    msg_callback({
                        'node': can_ids.NODE_BRAKE,
                        'can_id': can_ids.BRAKE_ID,
                        'seq': seq,
                        'data_dict': {'brake_pct': brake_pct},
                        'timestamp': time.time(),
                        'raw_bytes': signed_payload
                    })
                    
                seq = (seq + 1) % 65536
            else:
                logger.warning("Invalid HMAC on ADAS decision frame")

if __name__ == '__main__':
    stop_event = threading.Event()
    try:
        run(stop_event)
    except KeyboardInterrupt:
        logger.info("Stopping Brake ECU node.")
        stop_event.set()
