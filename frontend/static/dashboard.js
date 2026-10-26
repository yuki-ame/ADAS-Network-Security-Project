const socket = io();
roadSimulation.bind(socket);

// State
let msgCounts = {
    'radar': 0, 'camera': 0, 'adas_ecu': 0, 'gateway': 0, 'brake_ecu': 0
};
let alertCounts = {
    'spoof': 0, 'replay': 0, 'flood': 0
};
let totalMsgs = 0;
let totalAlerts = 0;
const nodeLastSeen = Object.fromEntries(Object.keys(msgCounts).map(node => [node, -Infinity]));
let simulationRunning = false;
let simulationStopping = false;
let activeAttack = null;
let controlRequest = null;
let statePoll = null;

function renderControls() {
    const offline = !socket.connected;
    const pending = controlRequest !== null;
    document.getElementById('btn-messages-start').disabled = offline || pending || simulationRunning || simulationStopping;
    document.getElementById('btn-messages-stop').disabled = offline || pending || !simulationRunning;
    document.getElementById('btn-launch').disabled = offline || pending || !simulationRunning || !!activeAttack;
    document.getElementById('btn-stop').disabled = offline || pending || !activeAttack;
    document.getElementById('messages-state').textContent = offline ? 'Disconnected'
        : controlRequest === 'start' ? 'Starting messages…'
        : controlRequest === 'stop' || simulationStopping ? 'Stopping messages…'
        : simulationRunning ? 'Messages running' : 'Messages stopped';
}

function applySimulationState(state) {
    simulationRunning = state.running;
    simulationStopping = state.stopping;
    activeAttack = state.attack_mode;
    document.getElementById('defense-toggle').checked = state.defense_enabled;
    if (!simulationRunning) {
        Object.keys(nodeLastSeen).forEach(node => { nodeLastSeen[node] = -Infinity; msgCounts[node] = 0; });
    }
    renderControls();
    updateNodeActivity();
    clearTimeout(statePoll);
    if (simulationStopping) statePoll = setTimeout(refreshSimulationState, 500);
}

async function refreshSimulationState() {
    try {
        const response = await fetch('/api/simulation/status');
        if (!response.ok) throw new Error('Unable to read message state');
        const state = await response.json();
        if (!controlRequest) applySimulationState(state);
    } catch (error) {
        addLogEntry(error.message, 'alert');
    }
}

async function sendControl(url, action, body) {
    controlRequest = action;
    renderControls();
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body || {}),
        });
        const data = await response.json();
        if ('running' in data) applySimulationState(data);
        if (!response.ok || data.error) throw new Error(data.error || 'The request failed');
    } catch (error) {
        addLogEntry(error.message, 'alert');
    } finally {
        controlRequest = null;
        renderControls();
        if (simulationStopping) refreshSimulationState();
    }
}

// Node activity reflects received telemetry, including disconnects and stale nodes.
function updateNodeActivity() {
    const now = performance.now();
    Object.keys(nodeLastSeen).forEach(node => {
        const status = document.querySelector(`#node-${node} .node-status`);
        const active = socket.connected && simulationRunning && now - nodeLastSeen[node] < 5000;
        status.textContent = active ? 'Active' : 'Inactive';
        status.className = `node-status ${active ? 'is-active' : 'is-inactive'}`;
        status.title = active ? 'Telemetry received within the last 5 seconds' : 'Disconnected or no recent telemetry';
    });
}

// Charts
Chart.defaults.font.family = 'Calibri, Candara, Arial, sans-serif';
Chart.defaults.color = '#475569';
Chart.defaults.borderColor = '#e2e8f0';
const ctxRate = document.getElementById('rateChart').getContext('2d');
const rateChart = new Chart(ctxRate, {
    type: 'line',
    data: {
        labels: Array(30).fill(''),
        datasets: [
            { label: 'Radar', data: Array(30).fill(0), borderColor: '#0f766e', tension: 0.1 },
            { label: 'Camera', data: Array(30).fill(0), borderColor: '#9333ea', tension: 0.1 },
            { label: 'ADAS', data: Array(30).fill(0), borderColor: '#a16207', tension: 0.1 },
            { label: 'Gateway', data: Array(30).fill(0), borderColor: '#c2410c', tension: 0.1 },
            { label: 'Brake', data: Array(30).fill(0), borderColor: '#2563eb', tension: 0.1 }
        ].map(dataset => ({ ...dataset, backgroundColor: dataset.borderColor, pointStyle: 'circle', pointRadius: 2 }))
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { usePointStyle: true, pointStyle: 'circle', boxWidth: 9, boxHeight: 9 } }
        },
        scales: {
            y: { beginAtZero: true, suggestedMax: 50 },
            x: { display: false }
        },
        animation: false
    }
});

const ctxAlert = document.getElementById('alertChart').getContext('2d');
const alertChart = new Chart(ctxAlert, {
    type: 'bar',
    data: {
        labels: ['Spoof', 'Replay', 'Flood'],
        datasets: [{
            label: 'Alerts',
            data: [0, 0, 0],
            backgroundColor: ['#dc2626', '#d97706', '#9333ea']
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: { beginAtZero: true, suggestedMax: 10 }
        }
    }
});

// Update rate chart every second
setInterval(() => {
    rateChart.data.datasets[0].data.push(msgCounts['radar']);
    rateChart.data.datasets[1].data.push(msgCounts['camera']);
    rateChart.data.datasets[2].data.push(msgCounts['adas_ecu']);
    rateChart.data.datasets[3].data.push(msgCounts['gateway']);
    rateChart.data.datasets[4].data.push(msgCounts['brake_ecu']);
    
    rateChart.data.datasets.forEach(ds => ds.data.shift());
    rateChart.update();
    
    // Reset counts
    Object.keys(msgCounts).forEach(k => msgCounts[k] = 0);
    updateNodeActivity();
}, 1000);

// Helper for UI
function addLogEntry(text, type = 'info') {
    const feed = document.getElementById('log-feed');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    const time = new Date().toISOString().split('T')[1].substring(0,8);
    entry.textContent = `[${time}] ${text}`;
    feed.prepend(entry);
    
    if (feed.children.length > 200) {
        feed.removeChild(feed.lastChild);
    }
}

// Socket events
socket.on('connect', () => {
    Object.keys(nodeLastSeen).forEach(node => nodeLastSeen[node] = -Infinity);
    updateNodeActivity();
    renderControls();
    refreshSimulationState();
    addLogEntry('Connected to server', 'system');
});

socket.on('disconnect', () => { updateNodeActivity(); renderControls(); });
socket.on('simulation_state', applySimulationState);

socket.on('new_message_batch', (msgs) => {
    if (!simulationRunning) return;
    totalMsgs += msgs.length;
    document.getElementById('stat-msgs').textContent = totalMsgs;
    
    msgs.forEach(msg => {
        if (msgCounts[msg.sender_node] !== undefined) {
            msgCounts[msg.sender_node]++;
            nodeLastSeen[msg.sender_node] = performance.now();
        }
    });
    updateNodeActivity();
});

socket.on('new_alert_batch', (alts) => {
    if (!simulationRunning) return;
    totalAlerts += alts.length;
    document.getElementById('stat-alerts').textContent = totalAlerts;
    
    alts.forEach(alert => {
        const atype = alert.alert_type.toLowerCase();
        if (alertCounts[atype] !== undefined) {
            alertCounts[atype]++;
        }
        addLogEntry(`ALERT: ${alert.alert_type} from ${alert.source_node} - ${alert.action_taken}`, 'alert');
    });
    
    alertChart.data.datasets[0].data = [
        alertCounts['spoof'],
        alertCounts['replay'],
        alertCounts['flood']
    ];
    alertChart.update();
});

socket.on('system_log', (data) => {
    addLogEntry(data.message, 'system');
});

socket.on('node_status_update', (data) => {
    const row = document.getElementById(`node-${data.node_name}`);
    // IDS security status is distinct from whether a node is still publishing.
    if (row) row.title = `IDS status: ${data.status}`;
});

// Controls
document.getElementById('btn-messages-start').addEventListener('click', () => {
    sendControl('/api/simulation/start', 'start');
});

document.getElementById('btn-messages-stop').addEventListener('click', () => {
    sendControl('/api/simulation/stop', 'stop');
});

document.getElementById('btn-launch').addEventListener('click', () => {
    const mode = document.getElementById('attack-mode').value;
    const rate = parseInt(document.getElementById('attack-rate').value);
    
    sendControl('/api/attack/start', 'attack-start', {mode, rate});
});

document.getElementById('btn-stop').addEventListener('click', () => {
    sendControl('/api/attack/stop', 'attack-stop');
});

document.getElementById('defense-toggle').addEventListener('change', (e) => {
    fetch('/api/defense/toggle', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: e.target.checked})
    });
});
