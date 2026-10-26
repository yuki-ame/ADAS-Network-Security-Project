import os
import sys
import time
import logging
import struct
import threading
from collections import deque
import can

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.can_ids import (
    CAN_ID_TO_NODE, HMAC_LEN_BY_ID,
    RATE_LIMIT_MSG_PER_SEC, RATE_LIMIT_WINDOW_SEC, NODE_ISOLATION_THRESHOLD
)
from defense.crypto_utils import split_and_verify

logger = logging.getLogger(__name__)

class IntrusionDetectionSystem:
    def __init__(self, alert_callback=None):
        self._enabled = True
        self.alert_callback = alert_callback
        
        self.lock = threading.Lock()
        
        # State tracking
        self.last_seq = {}         # (node_name, can_id) -> int
        self.rate_windows = {}     # node_name -> deque of timestamps
        self.alert_counts = {}     # node_name -> int
        self.blocklist = set()     # set of node_names
        
    def enable(self):
        with self.lock:
            self._enabled = True
            
    def disable(self):
        with self.lock:
            self._enabled = False
            
    @property
    def enabled(self) -> bool:
        with self.lock:
            return self._enabled
            
    def _trigger_alert(self, alert_type, node_name, action, can_id, details=""):
        if node_name not in self.alert_counts:
            self.alert_counts[node_name] = 0
            
        if action != 'isolated':
            self.alert_counts[node_name] += 1
            if self.alert_counts[node_name] >= NODE_ISOLATION_THRESHOLD:
                if node_name not in self.blocklist:
                    logger.warning(f"Node {node_name} ISOLATED (exceeded threshold).")
                    self.blocklist.add(node_name)
                    
        if self.alert_callback:
            self.alert_callback({
                'timestamp': time.time(),
                'alert_type': alert_type,
                'source_node': node_name,
                'action_taken': action,
                'can_id': can_id,
                'details': details
            })

    def inspect_frame(self, msg: can.Message) -> bool:
        with self.lock:
            if not self._enabled:
                return True
                
            can_id = msg.arbitration_id
            node_name = CAN_ID_TO_NODE.get(can_id, f"unknown_{hex(can_id)}")
            
            # Layer 4: Node Isolation Check
            if node_name in self.blocklist:
                self._trigger_alert('isolation_violation', node_name, 'isolated', can_id, "Node is isolated")
                return False
                
            # Layer 3: Rate Limiting
            now = time.time()
            if node_name not in self.rate_windows:
                self.rate_windows[node_name] = deque()
            
            window = self.rate_windows[node_name]
            window.append(now)
            while window and window[0] < now - RATE_LIMIT_WINDOW_SEC:
                window.popleft()
                
            if len(window) > RATE_LIMIT_MSG_PER_SEC:
                self._trigger_alert('flood', node_name, 'rate-limited', can_id, f"Rate {len(window)} exceeds {RATE_LIMIT_MSG_PER_SEC}/s")
                return False

            if can_id not in HMAC_LEN_BY_ID:
                self._trigger_alert('format_error', node_name, 'blocked', can_id, "Unknown CAN ID")
                return False

            # Layer 1: HMAC Verification
            hmac_len = HMAC_LEN_BY_ID[can_id]
            if len(msg.data) < hmac_len:
                self._trigger_alert('format_error', node_name, 'blocked', can_id, "Frame too short for HMAC")
                return False
                
            payload, mac, valid = split_and_verify(msg.data, hmac_len)
            if not valid:
                self._trigger_alert('spoof', node_name, 'blocked', can_id, "Invalid HMAC")
                return False
                
            # Layer 2: Sequence Check
            if len(payload) >= 2:
                seq = struct.unpack(">H", payload[:2])[0]
                state_key = (node_name, can_id)
                
                if state_key in self.last_seq:
                    last_seen_seq = self.last_seq[state_key]
                    
                    if seq <= last_seen_seq and (last_seen_seq - seq) < 30000:
                        self._trigger_alert('replay', node_name, 'blocked', can_id, f"Sequence {seq} <= {last_seen_seq}")
                        return False
                        
                self.last_seq[state_key] = seq
            else:
                self._trigger_alert('format_error', node_name, 'blocked', can_id, "Frame too short for seq num")
                return False
                
            return True

    def get_node_status(self, node_name) -> dict:
        with self.lock:
            status = 'isolated' if node_name in self.blocklist else 'active'
            alert_count = self.alert_counts.get(node_name, 0)
            
            last_seen = 0.0
            if node_name in self.rate_windows and self.rate_windows[node_name]:
                last_seen = self.rate_windows[node_name][-1]
                
            return {
                'status': status,
                'alert_count': alert_count,
                'last_seen': last_seen
            }
            
    def get_all_node_status(self) -> dict:
        with self.lock:
            nodes = set(list(CAN_ID_TO_NODE.values()) + list(self.rate_windows.keys()) + list(self.alert_counts.keys()))
            res = {}
            for node_name in nodes:
                status = 'isolated' if node_name in self.blocklist else 'active'
                alert_count = self.alert_counts.get(node_name, 0)
                last_seen = 0.0
                if node_name in self.rate_windows and self.rate_windows[node_name]:
                    last_seen = self.rate_windows[node_name][-1]
                res[node_name] = {
                    'status': status,
                    'alert_count': alert_count,
                    'last_seen': last_seen
                }
            return res
            
    def reset_node(self, node_name):
        with self.lock:
            self.alert_counts.pop(node_name, None)
            self.blocklist.discard(node_name)
            self.rate_windows.pop(node_name, None)
            keys_to_delete = [k for k in self.last_seq if k[0] == node_name]
            for k in keys_to_delete:
                del self.last_seq[k]
                
    def reset_all(self):
        with self.lock:
            self.last_seq.clear()
            self.rate_windows.clear()
            self.alert_counts.clear()
            self.blocklist.clear()
