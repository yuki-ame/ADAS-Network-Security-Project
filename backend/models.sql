CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time REAL,
    defense_enabled INTEGER DEFAULT 0,
    attack_type TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    sender_node TEXT,
    can_id INTEGER,
    payload TEXT,
    hmac_valid INTEGER,
    session_id INTEGER REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    alert_type TEXT,
    source_node TEXT,
    action_taken TEXT,
    session_id INTEGER REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS node_status (
    node_name TEXT PRIMARY KEY,
    status TEXT DEFAULT 'active',
    alert_count INTEGER DEFAULT 0,
    last_seen REAL
);
