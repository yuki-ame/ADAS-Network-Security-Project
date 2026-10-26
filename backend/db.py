import sqlite3
import threading
import time
import os
import sys
import csv

# Add parent directory to sys.path to allow importing common
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.can_ids import NODE_RADAR, NODE_CAMERA, NODE_ADAS, NODE_GATEWAY, NODE_BRAKE

if os.environ.get('VERCEL'):
    DB_FILE = '/tmp/adas_network.db'
else:
    DB_FILE = os.environ.get('DB_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'adas_network.db')))
SQL_FILE = os.path.join(os.path.dirname(__file__), 'models.sql')

_local = threading.local()

def get_db():
    if not hasattr(_local, 'conn'):
        _local.conn = sqlite3.connect(DB_FILE)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn

def init_db():
    conn = get_db()
    with open(SQL_FILE, 'r') as f:
        conn.executescript(f.read())
    
    # Initialize node_status rows
    nodes = [NODE_RADAR, NODE_CAMERA, NODE_ADAS, NODE_GATEWAY, NODE_BRAKE]
    now = time.time()
    for node in nodes:
        conn.execute(
            '''INSERT OR IGNORE INTO node_status (node_name, status, alert_count, last_seen) 
               VALUES (?, 'active', 0, ?)''', 
            (node, now)
        )
    conn.commit()

def create_session(defense_enabled, attack_type=None, notes=None) -> int:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO sessions (start_time, defense_enabled, attack_type, notes) VALUES (?, ?, ?, ?)',
        (time.time(), int(defense_enabled), attack_type, notes)
    )
    conn.commit()
    return cursor.lastrowid

def log_message(session_id, sender_node, can_id, payload_hex, hmac_valid):
    conn = get_db()
    conn.execute(
        'INSERT INTO messages (timestamp, sender_node, can_id, payload, hmac_valid, session_id) VALUES (?, ?, ?, ?, ?, ?)',
        (time.time(), sender_node, can_id, payload_hex, int(hmac_valid), session_id)
    )
    conn.commit()

def log_alert(session_id, alert_type, source_node, action_taken):
    conn = get_db()
    conn.execute(
        'INSERT INTO alerts (timestamp, alert_type, source_node, action_taken, session_id) VALUES (?, ?, ?, ?, ?)',
        (time.time(), alert_type, source_node, action_taken, session_id)
    )
    conn.commit()

def update_node_status(node_name, status, alert_count=None):
    conn = get_db()
    if alert_count is not None:
        conn.execute(
            'UPDATE node_status SET status = ?, alert_count = ?, last_seen = ? WHERE node_name = ?',
            (status, alert_count, time.time(), node_name)
        )
    else:
        conn.execute(
            'UPDATE node_status SET status = ?, last_seen = ? WHERE node_name = ?',
            (status, time.time(), node_name)
        )
    conn.commit()

def get_session_stats(session_id) -> dict:
    conn = get_db()
    msg_count = conn.execute('SELECT COUNT(*) FROM messages WHERE session_id = ?', (session_id,)).fetchone()[0]
    alert_count = conn.execute('SELECT COUNT(*) FROM alerts WHERE session_id = ?', (session_id,)).fetchone()[0]
    
    alerts_by_type = conn.execute(
        'SELECT alert_type, COUNT(*) FROM alerts WHERE session_id = ? GROUP BY alert_type',
        (session_id,)
    ).fetchall()
    
    breakdown = {row[0]: row[1] for row in alerts_by_type}
    
    return {
        'message_count': msg_count,
        'alert_count': alert_count,
        'alert_breakdown': breakdown
    }

def get_all_sessions() -> list[dict]:
    conn = get_db()
    rows = conn.execute('SELECT * FROM sessions ORDER BY id DESC').fetchall()
    return [dict(row) for row in rows]

def export_session_csv(session_id, output_dir):
    conn = get_db()
    os.makedirs(output_dir, exist_ok=True)
    
    msg_file = os.path.join(output_dir, f'session_{session_id}_messages.csv')
    with open(msg_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'timestamp', 'sender_node', 'can_id', 'payload', 'hmac_valid'])
        for row in conn.execute('SELECT id, timestamp, sender_node, can_id, payload, hmac_valid FROM messages WHERE session_id = ?', (session_id,)):
            writer.writerow(row)
            
    alert_file = os.path.join(output_dir, f'session_{session_id}_alerts.csv')
    with open(alert_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'timestamp', 'alert_type', 'source_node', 'action_taken'])
        for row in conn.execute('SELECT id, timestamp, alert_type, source_node, action_taken FROM alerts WHERE session_id = ?', (session_id,)):
            writer.writerow(row)
