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

logger = logging.getLogger("gateway")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

def run(stop_event, msg_callback=None, ids_callback=None):
    b = bus.get_bus()
    seq = 0
    
    last_summary_time = time.time()
    msg_counts = {id: 0 for id in can_ids.ALL_KNOWN_IDS}
    
    logger.info("Gateway node started.")
    
    while not stop_event.is_set():
        msg = b.recv(timeout=0.1)
        current_time = time.time()
        
        if msg is not None:
            # Log every frame
            logger.info(f"Frame RX: TS={msg.timestamp if msg.timestamp else current_time:.3f} ID=0x{msg.arbitration_id:03X} Data={msg.data.hex()}")
            
            if msg.arbitration_id in msg_counts:
                msg_counts[msg.arbitration_id] += 1
            else:
                msg_counts[msg.arbitration_id] = 1
                
            if ids_callback:
                ids_callback(msg)
                
        # Publish summary frame every 500ms
        if current_time - last_summary_time >= 0.5:
            # We send a summary frame from the gateway. 
            # The format is seq(2B) + origin_id(2B) + hmac(4B)
            payload = struct.pack(can_ids.FMT_GATEWAY_DATA, seq, can_ids.GATEWAY_ID)
            signed_payload = crypto_utils.sign_payload(payload, truncate=can_ids.HMAC_LEN_LONG)
            
            out_msg = Message(arbitration_id=can_ids.GATEWAY_ID, data=signed_payload, is_extended_id=False)
            try:
                b.send(out_msg)
            except Exception as e:
                logger.error(f"Failed to send Gateway summary: {e}")
                
            if msg_callback:
                msg_callback({
                    'node': can_ids.NODE_GATEWAY,
                    'can_id': can_ids.GATEWAY_ID,
                    'seq': seq,
                    'data_dict': {'counts': dict(msg_counts)},
                    'timestamp': current_time,
                    'raw_bytes': signed_payload
                })
                
            seq = (seq + 1) % 65536
            last_summary_time = current_time

if __name__ == '__main__':
    stop_event = threading.Event()
    try:
        run(stop_event)
    except KeyboardInterrupt:
        logger.info("Stopping Gateway node.")
        stop_event.set()
