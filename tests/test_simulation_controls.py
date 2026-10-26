"""Exercise manual traffic controls with real CAN nodes and SocketIO events."""
import importlib
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(scope='module')
def server(tmp_path_factory):
    backend = importlib.import_module('backend.app')
    db = importlib.import_module('backend.db')
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(db, 'DB_FILE', str(tmp_path_factory.mktemp('traffic-controls') / 'test.db'))
        patch.setattr(db, '_local', threading.local())
        backend.initialize_system()
        yield backend
        backend.stop_nodes()


@pytest.fixture
def dashboard(server):
    client = server.app.test_client()
    server.stop_nodes()
    events = server.socketio.test_client(server.app)
    try:
        yield server, client, events
    finally:
        server.stop_nodes()
        client.post('/api/defense/toggle', json={'enabled': False})
        events.disconnect()


def message_count():
    db = importlib.import_module('backend.db')
    return db.get_db().execute('SELECT COUNT(*) FROM messages').fetchone()[0]


def wait_for_events(events, predicate, timeout=8):
    received = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        received.extend(events.get_received())
        if predicate(received):
            return received
        time.sleep(0.03)
    pytest.fail('Timed out waiting for expected telemetry/events')


def test_server_opens_with_messages_stopped(dashboard):
    server, client, events = dashboard
    assert client.get('/').status_code == 200
    assert client.get('/api/simulation/status').json['running'] is False
    assert not any(thread.is_alive() for thread in server.node_threads)
    assert all(node['status'] == 'inactive' for node in client.get('/api/nodes/status').json.values())
    count = message_count()
    time.sleep(0.25)
    assert message_count() == count
    assert not any(event['name'] == 'new_message_batch' for event in events.get_received())


def test_start_is_idempotent_and_stop_restart_controls_real_traffic(dashboard):
    server, client, events = dashboard
    assert client.post('/api/simulation/start').json['running'] is True
    original_threads = list(server.node_threads)
    assert client.post('/api/simulation/start').status_code == 200
    assert server.node_threads == original_threads
    assert len(original_threads) == 5

    def all_nodes_reported(received):
        nodes = {message['sender_node']
                 for event in received if event['name'] == 'new_message_batch'
                 for message in event['args'][0]}
        return nodes == {'radar', 'camera', 'adas_ecu', 'brake_ecu', 'gateway'}

    wait_for_events(events, all_nodes_reported)
    stopped = client.post('/api/simulation/stop')
    assert stopped.status_code == 200
    assert stopped.json['running'] is False
    assert stopped.json['stopping'] is False
    assert all(not thread.is_alive() for thread in original_threads)
    count = message_count()
    time.sleep(0.25)
    assert message_count() == count
    assert client.post('/api/simulation/stop').status_code == 200

    events.get_received()
    assert client.post('/api/simulation/start').json['running'] is True
    assert len(server.node_threads) == 5
    assert not any(thread in original_threads for thread in server.node_threads)
    wait_for_events(events, all_nodes_reported)


def test_attack_requires_running_messages(dashboard):
    _, client, _ = dashboard
    response = client.post('/api/attack/start', json={'mode': 'spoof', 'rate': 10})
    assert response.status_code == 409
    assert 'Start Messages' in response.json['error']


def test_stop_messages_also_stops_attack_after_ids_alert(dashboard):
    server, client, events = dashboard
    client.post('/api/defense/toggle', json={'enabled': True})
    client.post('/api/simulation/start')
    response = client.post('/api/attack/start', json={'mode': 'spoof', 'rate': 10})
    assert response.status_code == 200
    attack_thread = server.attacker_thread
    wait_for_events(events, lambda received: any(event['name'] == 'new_alert_batch' for event in received))
    response = client.post('/api/simulation/stop')
    assert response.status_code == 200
    assert response.json['running'] is False
    assert response.json['stopping'] is False
    assert response.json['attack_mode'] is None
    assert not attack_thread.is_alive()
    assert all(not thread.is_alive() for thread in server.node_threads)
