"""
app.py — Flask + Flask-SocketIO server for the ADAS Network Security Dashboard.

Orchestrates all ADAS nodes, the attacker, and the IDS. Pushes real-time
events to the browser via SocketIO and logs everything to SQLite.
"""

import eventlet
eventlet.monkey_patch()

import os
import sys
import time
import threading
import logging

# Ensure project root is on sys.path for all imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

from backend.db import (
    init_db, create_session, log_message, log_alert, update_node_status,
    get_all_sessions, get_session_stats, export_session_csv
)
from common.can_ids import (
    NODE_RADAR, NODE_CAMERA, NODE_ADAS, NODE_GATEWAY, NODE_BRAKE,
    CAN_ID_TO_NODE
)

# Import nodes
from nodes.radar import run as run_radar
from nodes.camera import run as run_camera
from nodes.adas_ecu import run as run_adas
from nodes.brake_ecu import run as run_brake
from nodes.gateway import run as run_gateway

# Import attacker (function-based API)
from attacker.attacker import run_attack

# Import IDS (class-based API)
from defense.ids import IntrusionDetectionSystem

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("app")

# ──────────────────────────────────────────────
# Flask + SocketIO
# ──────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend', 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static'),
)
app.config['SECRET_KEY'] = 'adas-network-security-2025'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

# ──────────────────────────────────────────────
# Global state
# ──────────────────────────────────────────────
current_session_id = None
defense_enabled = False
ids_instance = None              # IntrusionDetectionSystem
attacker_stop_event = None       # threading.Event for stopping attacks
attacker_thread = None           # Thread running the attack
nodes_stop_event = threading.Event()
nodes_started = False

# SocketIO batching (100ms intervals to avoid flooding the browser)
message_batch = []
alert_batch = []
batch_lock = threading.Lock()


# ──────────────────────────────────────────────
# Batching worker — pushes accumulated events every 100ms
# ──────────────────────────────────────────────
def socket_batch_worker():
    """Drain message and alert queues and emit to all connected clients."""
    while True:
        eventlet.sleep(0.1)
        with batch_lock:
            msgs = message_batch[:]
            alts = alert_batch[:]
            message_batch.clear()
            alert_batch.clear()

        if msgs:
            socketio.emit('new_message_batch', msgs)
        if alts:
            socketio.emit('new_alert_batch', alts)


# ──────────────────────────────────────────────
# Callbacks — called by nodes, gateway, attacker, and IDS
# ──────────────────────────────────────────────
def node_msg_callback(msg_data: dict):
    """
    Called by each node when it sends or processes a CAN frame.
    msg_data keys: node, can_id, seq, data_dict, timestamp, raw_bytes
    """
    payload_hex = msg_data.get('raw_bytes', b'').hex()
    sender = msg_data.get('node', 'unknown')
    can_id = msg_data.get('can_id', 0)

    # Log to DB
    if current_session_id:
        try:
            log_message(current_session_id, sender, can_id, payload_hex, 1)
        except Exception:
            pass  # DB errors should not crash nodes

    # Update node status
    try:
        update_node_status(sender, 'active')
    except Exception:
        pass

    # Queue for browser
    event = {
        'timestamp': msg_data.get('timestamp', time.time()),
        'sender_node': sender,
        'can_id': hex(can_id),
        'payload_hex': payload_hex,
        'hmac_valid': True,
        'seq': msg_data.get('seq', 0),
        'data': msg_data.get('data_dict', {}),
    }
    with batch_lock:
        message_batch.append(event)


def ids_alert_callback(alert_data: dict):
    """
    Called by the IDS when it raises an alert.
    alert_data keys: timestamp, alert_type, source_node, action_taken, can_id, details
    """
    # Log to DB
    if current_session_id:
        try:
            log_alert(
                current_session_id,
                alert_data['alert_type'],
                alert_data['source_node'],
                alert_data['action_taken'],
            )
        except Exception:
            pass

    # Update node status
    try:
        status = 'blocked' if alert_data['action_taken'] == 'isolated' else 'suspicious'
        update_node_status(alert_data['source_node'], status)
    except Exception:
        pass

    # Queue for browser
    event = {
        'timestamp': alert_data.get('timestamp', time.time()),
        'alert_type': alert_data['alert_type'],
        'source_node': alert_data['source_node'],
        'action_taken': alert_data['action_taken'],
        'details': alert_data.get('details', ''),
    }
    with batch_lock:
        alert_batch.append(event)

    # Push node status update immediately
    socketio.emit('node_status_update', {
        'node_name': alert_data['source_node'],
        'status': 'blocked' if alert_data['action_taken'] == 'isolated' else 'suspicious',
        'alert_count': ids_instance.get_node_status(alert_data['source_node'])['alert_count'] if ids_instance else 0,
    })


def gateway_ids_callback(can_msg):
    """
    Called by the gateway for every received CAN frame.
    Passes the frame to the IDS for inspection (if defense is enabled).
    """
    if ids_instance and ids_instance.enabled:
        ids_instance.inspect_frame(can_msg)


# ──────────────────────────────────────────────
# System startup — init DB, start nodes
# ──────────────────────────────────────────────
def start_nodes():
    """Start all 5 ADAS nodes as daemon threads."""
    global nodes_started, current_session_id

    if nodes_started:
        return

    init_db()
    current_session_id = create_session(defense_enabled, notes="System startup")

    # Start batch worker
    eventlet.spawn(socket_batch_worker)

    # Start nodes
    threading.Thread(target=run_radar,    args=(nodes_stop_event, node_msg_callback), daemon=True, name="radar").start()
    threading.Thread(target=run_camera,   args=(nodes_stop_event, node_msg_callback), daemon=True, name="camera").start()
    threading.Thread(target=run_adas,     args=(nodes_stop_event, node_msg_callback), daemon=True, name="adas_ecu").start()
    threading.Thread(target=run_brake,    args=(nodes_stop_event, node_msg_callback), daemon=True, name="brake_ecu").start()
    threading.Thread(target=run_gateway,  args=(nodes_stop_event, node_msg_callback),
                     kwargs={'ids_callback': gateway_ids_callback}, daemon=True, name="gateway").start()

    nodes_started = True
    logger.info("All 5 ADAS nodes started.")
    socketio.emit('system_log', {'timestamp': time.time(), 'message': 'All nodes started'})


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    return jsonify(get_all_sessions())


@app.route('/api/sessions', methods=['POST'])
def new_session():
    global current_session_id
    data = request.json or {}
    current_session_id = create_session(defense_enabled, notes=data.get('notes', 'Manual session'))
    socketio.emit('system_log', {
        'timestamp': time.time(),
        'message': f'New session created: {current_session_id}'
    })
    return jsonify({'session_id': current_session_id})


@app.route('/api/attack/start', methods=['POST'])
def start_attack():
    global attacker_stop_event, attacker_thread, current_session_id

    data = request.json or {}
    mode = data.get('mode', 'spoof')
    rate = data.get('rate', 5000)

    # Check if attack is already running
    if attacker_thread and attacker_thread.is_alive():
        return jsonify({'error': 'Attack already running'}), 400

    # Create a new session for this attack run
    current_session_id = create_session(defense_enabled, attack_type=mode, notes=f'Attack: {mode}')

    # Start the attack in a background thread
    attacker_stop_event = threading.Event()
    attacker_thread = threading.Thread(
        target=run_attack,
        args=(mode, attacker_stop_event, rate),
        daemon=True,
        name=f"attacker-{mode}",
    )
    attacker_thread.start()

    logger.info(f"Attack started: mode={mode}, rate={rate}")
    socketio.emit('system_log', {
        'timestamp': time.time(),
        'message': f'Attack started: {mode} (rate={rate} msg/s)'
    })
    return jsonify({'status': 'Attack started', 'mode': mode, 'session_id': current_session_id})


@app.route('/api/attack/stop', methods=['POST'])
def stop_attack():
    global attacker_stop_event, attacker_thread

    if attacker_stop_event and attacker_thread and attacker_thread.is_alive():
        attacker_stop_event.set()
        attacker_thread.join(timeout=3.0)
        logger.info("Attack stopped.")
        socketio.emit('system_log', {'timestamp': time.time(), 'message': 'Attack stopped'})
        return jsonify({'status': 'Attack stopped'})

    return jsonify({'status': 'No attack running'})


@app.route('/api/defense/toggle', methods=['POST'])
def toggle_defense():
    global defense_enabled, ids_instance, current_session_id

    data = request.json or {}
    defense_enabled = data.get('enabled', False)

    if defense_enabled:
        ids_instance = IntrusionDetectionSystem(alert_callback=ids_alert_callback)
        ids_instance.enable()
        logger.info("IDS defense ENABLED")
    else:
        if ids_instance:
            ids_instance.disable()
        ids_instance = None
        logger.info("IDS defense DISABLED")

    current_session_id = create_session(
        defense_enabled,
        notes=f"Defense {'enabled' if defense_enabled else 'disabled'}"
    )

    socketio.emit('system_log', {
        'timestamp': time.time(),
        'message': f"IDS Defense {'ENABLED' if defense_enabled else 'DISABLED'}"
    })
    return jsonify({'status': 'Defense updated', 'enabled': defense_enabled, 'session_id': current_session_id})


@app.route('/api/nodes/status', methods=['GET'])
def get_nodes_status():
    if ids_instance:
        return jsonify(ids_instance.get_all_node_status())
    # Fallback: all active
    return jsonify({
        name: {'status': 'active', 'alert_count': 0, 'last_seen': time.time()}
        for name in [NODE_RADAR, NODE_CAMERA, NODE_ADAS, NODE_GATEWAY, NODE_BRAKE]
    })


@app.route('/api/defense/reset', methods=['POST'])
def reset_defense():
    if ids_instance:
        ids_instance.reset_all()
        # Reset node status in DB
        for name in [NODE_RADAR, NODE_CAMERA, NODE_ADAS, NODE_GATEWAY, NODE_BRAKE]:
            update_node_status(name, 'active', alert_count=0)
        socketio.emit('system_log', {'timestamp': time.time(), 'message': 'IDS state reset'})
    return jsonify({'status': 'Reset complete'})


@app.route('/api/export/<int:session_id>', methods=['GET'])
def export_session(session_id):
    output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'results'))
    export_session_csv(session_id, output_dir)
    return jsonify({'status': 'exported', 'directory': output_dir})


@app.route('/api/sessions/<int:session_id>/stats', methods=['GET'])
def session_stats(session_id):
    return jsonify(get_session_stats(session_id))


# ──────────────────────────────────────────────
# SocketIO events
# ──────────────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    logger.info("Browser client connected")
    socketio.emit('system_log', {
        'timestamp': time.time(),
        'message': f'Dashboard connected | Session: {current_session_id} | Defense: {"ON" if defense_enabled else "OFF"}'
    })


# Auto-initialize nodes if running under hosted WSGI/serverless environments
if os.environ.get('VERCEL') or os.environ.get('RENDER'):
    try:
        start_nodes()
    except Exception as err:
        logger.warning(f"Could not auto-start nodes: {err}")

# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────
if __name__ == '__main__':
    start_nodes()
    logger.info("Starting dashboard on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)
