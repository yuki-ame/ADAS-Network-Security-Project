const socket = io();

// State
let msgCounts = {
    'radar': 0, 'camera': 0, 'adas_ecu': 0, 'gateway': 0, 'brake_ecu': 0
};
let alertCounts = {
    'spoof': 0, 'replay': 0, 'flood': 0
};
let totalMsgs = 0;
let totalAlerts = 0;

// Charts
const ctxRate = document.getElementById('rateChart').getContext('2d');
const rateChart = new Chart(ctxRate, {
    type: 'line',
    data: {
        labels: Array(30).fill(''),
        datasets: [
            { label: 'Radar', data: Array(30).fill(0), borderColor: '#00ffcc', tension: 0.1 },
            { label: 'Camera', data: Array(30).fill(0), borderColor: '#ff00cc', tension: 0.1 },
            { label: 'ADAS', data: Array(30).fill(0), borderColor: '#ffff00', tension: 0.1 },
            { label: 'Gateway', data: Array(30).fill(0), borderColor: '#ff6600', tension: 0.1 },
            { label: 'Brake', data: Array(30).fill(0), borderColor: '#3366ff', tension: 0.1 }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
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
            backgroundColor: ['#ff3333', '#ff9933', '#cc33ff']
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
    addLogEntry('Connected to server', 'system');
});

socket.on('new_message_batch', (msgs) => {
    totalMsgs += msgs.length;
    document.getElementById('stat-msgs').textContent = totalMsgs;
    
    msgs.forEach(msg => {
        if (msgCounts[msg.sender_node] !== undefined) {
            msgCounts[msg.sender_node]++;
        }
    });
});

socket.on('new_alert_batch', (alts) => {
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
    if (data.message.includes('session created:')) {
        document.getElementById('current-session-id').textContent = data.message.split(': ')[1];
    }
});

socket.on('node_status_update', (data) => {
    const card = document.getElementById(`card-${data.node_name}`);
    if (card) {
        const ind = card.querySelector('.indicator');
        const txt = card.querySelector('.status-text');
        
        card.className = `node-card status-${data.status}`;
        txt.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);
    }
});

// Controls
document.getElementById('btn-launch').addEventListener('click', () => {
    const mode = document.getElementById('attack-mode').value;
    const rate = parseInt(document.getElementById('attack-rate').value);
    
    fetch('/api/attack/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mode, rate})
    }).then(res => res.json()).then(data => {
        if (!data.error) {
            document.getElementById('btn-launch').disabled = true;
            document.getElementById('btn-stop').disabled = false;
        } else {
            alert(data.error);
        }
    });
});

document.getElementById('btn-stop').addEventListener('click', () => {
    fetch('/api/attack/stop', { method: 'POST' })
    .then(() => {
        document.getElementById('btn-launch').disabled = false;
        document.getElementById('btn-stop').disabled = true;
    });
});

document.getElementById('defense-toggle').addEventListener('change', (e) => {
    fetch('/api/defense/toggle', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: e.target.checked})
    });
});
