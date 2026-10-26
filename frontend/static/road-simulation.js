/* Live CAN visualization. Road motion is illustrative, not a vehicle physics model. */
const roadSimulation = (() => {
    const canvas = document.getElementById('road-canvas');
    const ctx = canvas.getContext('2d');
    const elements = Object.fromEntries(
        ['speed', 'brake', 'distance', 'status', 'detail', 'security', 'pause']
            .map(name => [name, document.getElementById(`road-${name}`)])
    );
    const objects = ['No object', 'Vehicle', 'Pedestrian', 'Cyclist'];
    const state = {
        connected: false, running: null, distance: null, displayedDistance: 20,
        relativeSpeed: 0, object: 0, confidence: 0, sceneObject: 0,
        brake: null, decision: 0, speed: 65, roadOffset: 0,
        radarAt: 0, brakeAt: 0, cameraAt: 0, objectAt: 0,
        defense: false, attack: null, alert: null, shieldUntil: 0,
        paused: matchMedia('(prefers-reduced-motion: reduce)').matches,
        width: 360, height: 160, lastFrame: 0, lastHud: 0,
    };
    const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

    function resize() {
        const rect = canvas.parentElement.getBoundingClientRect();
        state.width = rect.width;
        state.height = rect.height;
        const ratio = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.round(rect.width * ratio);
        canvas.height = Math.round(rect.height * ratio);
        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        draw(performance.now());
    }
    new ResizeObserver(resize).observe(canvas.parentElement);

    function receiveMessages(messages) {
        if (state.running === false) return;
        const now = performance.now();
        for (const msg of messages) {
            const data = msg.data || {};
            // Read source telemetry only; echoed or replayed frames are not ground truth.
            if (msg.sender_node === 'radar' && Number(msg.can_id) === 0x100 && Number.isFinite(data.distance_cm)) {
                state.distance = data.distance_cm / 100;
                state.relativeSpeed = Number(data.speed) / 10;
                state.radarAt = now;
            } else if (msg.sender_node === 'camera' && Number(msg.can_id) === 0x101 && Number.isInteger(data.obj_class)) {
                state.object = clamp(data.obj_class, 0, 3);
                state.confidence = Number(data.confidence) || 0;
                state.cameraAt = now;
            } else if (msg.sender_node === 'brake_ecu' && Number(msg.can_id) === 0x300 && Number.isFinite(data.brake_pct)) {
                state.brake = clamp(data.brake_pct, 0, 100);
                state.brakeAt = now;
            } else if (msg.sender_node === 'adas_ecu' && Number(msg.can_id) === 0x200 && Number.isInteger(data.decision)) {
                state.decision = data.decision;
            }
        }
    }

    function receiveAlerts(alerts) {
        const now = performance.now();
        for (const alert of alerts) {
            state.alert = { ...alert, at: now };
            if (['blocked', 'isolated', 'rate-limited'].includes(alert.action_taken)) {
                state.shieldUntil = now + 900;
            }
        }
    }

    function receiveLog({ message = '' }) {
        const attackMatch = message.match(/Attack started:\s*(spoof|replay|flood)/i);
        if (attackMatch) state.attack = attackMatch[1].toLowerCase();
        if (message.includes('Attack stopped')) state.attack = null;
        if (/Defense:\s*ON|IDS Defense ENABLED/.test(message)) state.defense = true;
        if (/Defense:\s*OFF|IDS Defense DISABLED/.test(message)) {
            state.defense = false;
            state.alert = null;
            state.shieldUntil = 0;
        }
    }

    function updateHud(now) {
        const live = state.connected && state.running !== false && state.radarAt > 0 && now - state.radarAt < 2500;
        const brakeLive = live && state.brakeAt > 0 && now - state.brakeAt < 2500;
        const cameraLive = live && state.cameraAt > 0 && now - state.cameraAt < 2500;
        elements.speed.textContent = live ? Math.round(state.speed) : '—';
        elements.brake.textContent = brakeLive ? state.brake : '—';
        elements.distance.textContent = live ? state.distance.toFixed(1) : '—';
        elements.security.textContent = state.defense ? 'IDS ON' : 'IDS OFF';
        elements.security.classList.toggle('is-enabled', state.defense);
        let status = 'Normal cruise', tone = 'normal';
        if (!live) {
            status = !state.connected ? 'Connection lost' : state.running === false ? 'Messages stopped' : 'Waiting for telemetry';
            tone = 'muted';
        }
        else if (!brakeLive) { status = 'Brake telemetry stale'; tone = 'warning'; }
        else if (state.brake >= 100) { status = 'Emergency braking'; tone = 'danger'; }
        else if (state.brake > 0) { status = 'Caution · braking'; tone = 'warning'; }
        else if (state.distance < 5) { status = 'Critical proximity'; tone = 'danger'; }
        else if (state.distance < 10) { status = 'Caution · close obstacle'; tone = 'warning'; }
        elements.status.textContent = status;
        elements.status.dataset.tone = tone;
        let detail = 'Live radar, camera & brakes · illustrative vehicle motion';
        if (live) {
            const detection = cameraLive ? `${objects[state.object]}${state.object ? ` ${state.confidence}%` : ''}` : 'Camera stale';
            detail = `${detection} · relative speed ${state.relativeSpeed.toFixed(1)} km/h · motion model`;
        }
        if (live && state.alert && now - state.alert.at < 3000) {
            const alert = state.alert;
            detail = `IDS: ${alert.alert_type.replace(/_/g, ' ')} · ${alert.action_taken} · ${alert.details || alert.source_node}`;
        } else if (live && state.attack === 'spoof') {
            detail = 'Spoof attempt: untrusted 2 m echo · brakes follow the real ECU';
        } else if (live && state.attack === 'replay') {
            detail = 'Replay active · stale radar frames injected onto the bus';
        } else if (live && state.attack === 'flood') {
            detail = 'Flood active · watching live telemetry for delays';
        }
        if (!live) detail = 'Motion held until fresh radar telemetry arrives.';
        if (state.connected && state.running === false) detail = 'Press Start Messages to begin the road simulation.';
        elements.detail.textContent = detail;
        canvas.setAttribute('aria-label', `${status}. Radar gap ${elements.distance.textContent} metres. Brake ${elements.brake.textContent} percent. Modeled speed ${elements.speed.textContent} kilometres per hour. ${detail}`);
        elements.pause.textContent = state.paused ? 'Resume' : 'Pause';
        elements.pause.setAttribute('aria-pressed', String(state.paused));
        elements.pause.setAttribute('aria-label', state.paused ? 'Resume road animation' : 'Pause road animation');
    }

    function box(x, y, width, height, radius, fill, stroke) {
        ctx.beginPath();
        ctx.roundRect(x, y, width, height, radius);
        if (fill) { ctx.fillStyle = fill; ctx.fill(); }
        if (stroke) { ctx.strokeStyle = stroke; ctx.stroke(); }
    }

    function text(label, x, y, color = '#64748b', size = 9, align = 'left') {
        ctx.fillStyle = color;
        ctx.font = `600 ${size}px Calibri, Candara, Arial, sans-serif`;
        ctx.textAlign = align;
        ctx.fillText(label, x, y);
    }

    function car(x, y, color, braking = false, ego = false) {
        ctx.save();
        ctx.translate(x, y);
        box(-30, -17, 62, 35, 9, '#00000050');
        [-16, 11].forEach(wheelY => {
            box(-19, wheelY, 13, 5, 2, '#060c15');
            box(12, wheelY, 13, 5, 2, '#060c15');
        });
        box(-29, -14, 58, 28, 8, color, ego ? '#b2ffed' : '#c1d0e0');
        box(-12, -10, 27, 20, 4, '#18324b');
        box(9, -9, 5, 18, 1, '#7ab8cd');
        box(-11, -9, 4, 18, 1, '#496e83');
        box(-1, -8, 8, 16, 2, ego ? '#3cafac' : '#607c9e');
        if (braking) { ctx.shadowColor = '#ff424f'; ctx.shadowBlur = 15; }
        box(-29, -11, 4, 7, 1, braking ? '#ff424f' : '#a74150');
        box(-29, 4, 4, 7, 1, braking ? '#ff424f' : '#a74150');
        ctx.shadowBlur = 0;
        box(26, -11, 3, 6, 1, '#f4f4ca');
        box(26, 5, 3, 6, 1, '#f4f4ca');
        ctx.restore();
    }

    function person(x, y, cyclist) {
        ctx.save();
        ctx.translate(x, y);
        ctx.strokeStyle = '#f1c77c';
        ctx.lineWidth = 3;
        if (cyclist) {
            ctx.strokeStyle = '#9daec5';
            [-10, 10].forEach(wheelX => {
                ctx.beginPath(); ctx.arc(wheelX, 6, 7, 0, Math.PI * 2); ctx.stroke();
            });
            ctx.beginPath(); ctx.moveTo(-10, 6); ctx.lineTo(0, -3); ctx.lineTo(10, 6); ctx.lineTo(-10, 6); ctx.stroke();
        }
        ctx.fillStyle = '#f1c77c';
        ctx.beginPath(); ctx.arc(0, -8, 6, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = '#f1c77c';
        ctx.beginPath();
        ctx.moveTo(0, -2); ctx.lineTo(0, 9);
        ctx.moveTo(-8, 1); ctx.lineTo(8, 1);
        ctx.moveTo(-7, 16); ctx.lineTo(0, 9); ctx.lineTo(7, 16);
        ctx.stroke();
        ctx.restore();
    }

    function draw(now) {
        const w = state.width, h = state.height;
        if (!w || !h) return;
        const live = state.connected && state.running !== false && state.radarAt > 0 && now - state.radarAt < 2500;
        const braking = live && now - state.brakeAt < 2500 && state.brake > 0;
        const gap = state.displayedDistance;
        const color = gap < 5 ? '#b91c1c' : gap < 10 ? '#b45309' : '#0f766e';
        const y = h * 0.56, egoX = Math.max(45, w * 0.18), nose = egoX + 29;
        const obstacleX = nose + 38 + clamp(gap / 20, 0, 1) * Math.max(30, w - nose - 84);
        const reach = Math.max(25, obstacleX - nose);
        ctx.clearRect(0, 0, w, h);
        ctx.fillStyle = '#eef4ef'; ctx.fillRect(0, 0, w, h);
        ctx.fillStyle = '#e2e8ec'; ctx.fillRect(0, h * 0.18, w, h * 0.68);
        // Road edges and moving markings follow modeled vehicle speed.
        ctx.fillStyle = '#94a3a0';
        ctx.fillRect(0, h * 0.2, w, 2); ctx.fillRect(0, h * 0.84, w, 2);
        ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 2; ctx.setLineDash([24, 23]);
        ctx.lineDashOffset = state.roadOffset;
        [0.33, 0.77].forEach(lane => {
            ctx.beginPath(); ctx.moveTo(0, h * lane); ctx.lineTo(w, h * lane); ctx.stroke();
        });
        ctx.setLineDash([]);
        for (let x = -(state.roadOffset % 65); x < w; x += 65) {
            box(x, h * 0.08, 14, 3, 1, '#a6bcae');
            box(x, h * 0.93, 14, 3, 1, '#a6bcae');
        }
        // Radar sector and range rings.
        ctx.save();
        if (gap < 5 && live && !state.paused) ctx.globalAlpha = 0.7 + Math.sin(now / 130) * 0.3;
        const beam = ctx.createLinearGradient(nose, 0, nose + reach, 0);
        beam.addColorStop(0, `${color}40`); beam.addColorStop(1, `${color}08`);
        ctx.beginPath(); ctx.moveTo(nose, y);
        ctx.lineTo(nose + reach, y - h * 0.17); ctx.lineTo(nose + reach, y + h * 0.17); ctx.closePath();
        ctx.fillStyle = beam; ctx.fill();
        ctx.strokeStyle = `${color}60`; ctx.lineWidth = 1;
        for (let i = 1; i <= 3; i++) {
            const r = reach * i / 3;
            ctx.beginPath(); ctx.ellipse(nose, y, r, h * 0.17 * i / 3, 0, -0.95, 0.95); ctx.stroke();
        }
        ctx.restore();
        if (braking && state.brake >= 100 && state.speed > 4) {
            ctx.strokeStyle = '#050a12b0'; ctx.lineWidth = 3;
            [-11, 11].forEach(offset => {
                ctx.beginPath(); ctx.moveTo(egoX - 28, y + offset); ctx.lineTo(Math.max(0, egoX - 70), y + offset); ctx.stroke();
                ctx.fillStyle = '#bac6d333';
                for (let i = 0; i < 3; i++) {
                    ctx.beginPath(); ctx.arc(egoX - 32 - i * 8, y + offset - i * 2, 3 + i * 2, 0, Math.PI * 2); ctx.fill();
                }
            });
        }
        car(egoX, y, '#20ada4', braking, true);
        text('EGO / ADAS', egoX, y + 29, '#115e59', 8, 'center');
        if (state.sceneObject === 1) car(obstacleX, y, '#7895b8');
        else if (state.sceneObject > 1) person(obstacleX, y, state.sceneObject === 3);
        else {
            ctx.strokeStyle = `${color}80`; ctx.setLineDash([3, 3]);
            ctx.strokeRect(obstacleX - 15, y - 17, 30, 34); ctx.setLineDash([]);
        }
        text(state.sceneObject ? objects[state.sceneObject].toUpperCase() : 'RADAR RETURN', obstacleX, y + 29, '#334155', 8, 'center');
        text(live ? `${gap.toFixed(1)} m` : 'NO LIVE DATA', (nose + obstacleX) / 2, y - h * 0.2, live ? color : '#64748b', 10, 'center');
        text('FORWARD →', 8, 13, '#4b6354', 7);
        if (live && state.attack === 'spoof') {
            const ghostX = Math.min(obstacleX, nose + 48);
            ctx.save();
            ctx.globalAlpha = state.paused ? 0.7 : 0.45 + Math.sin(now / 170) * 0.2;
            ctx.strokeStyle = '#be185d'; ctx.setLineDash([4, 3]);
            ctx.strokeRect(ghostX - 10, y - 19, 20, 38); ctx.setLineDash([]);
            text('UNTRUSTED 2 m', ghostX, h * 0.96, '#9d174d', 7, 'center');
            ctx.restore();
        }
        if (live && state.attack === 'replay') text('STALE FRAME INJECTION', w / 2, h * 0.96, '#92400e', 7, 'center');
        if (live && state.attack === 'flood') text('CAN FLOOD ACTIVE', w / 2, h * 0.96, '#7e22ce', 7, 'center');
        if (live && now < state.shieldUntil) {
            ctx.save(); ctx.translate(egoX, y);
            ctx.strokeStyle = '#1d4ed8'; ctx.lineWidth = 2;
            ctx.shadowColor = '#52b9ff'; ctx.shadowBlur = 10;
            ctx.beginPath(); ctx.moveTo(0, -29); ctx.lineTo(39, -18); ctx.lineTo(35, 18);
            ctx.quadraticCurveTo(0, 45, -35, 18); ctx.lineTo(-39, -18); ctx.closePath(); ctx.stroke();
            ctx.restore();
            text('IDS FLAGGED', egoX, h * 0.96, '#1d4ed8', 7, 'center');
        }
        if (!live || state.paused) {
            ctx.fillStyle = '#ffffff59'; ctx.fillRect(0, 0, w, h);
        }
    }

    function animate(now) {
        const dt = Math.min((now - (state.lastFrame || now)) / 1000, 0.1);
        state.lastFrame = now;
        const live = state.connected && state.running !== false && state.radarAt > 0 && now - state.radarAt < 2500;
        if (live && !state.paused && !document.hidden) {
            const brakeLive = state.brakeAt > 0 && now - state.brakeAt < 2500;
            if (brakeLive) {
                // Cruise acceleration / brake deceleration; radar speed is relative, not ego speed.
                const acceleration = state.brake >= 100 ? -8.8 : state.brake > 0 ? -2 : state.speed < 65 ? 1.8 : 0;
                state.speed = clamp(state.speed + acceleration * 3.6 * dt, 0, 65);
                state.roadOffset = (state.roadOffset + state.speed / 3.6 * 6 * dt) % 3055;
            }
            state.displayedDistance += (state.distance - state.displayedDistance) * (1 - Math.exp(-8 * dt));
            // Hold each camera silhouette briefly so 10 Hz class changes remain readable.
            if (now - state.objectAt > 650) {
                state.sceneObject = now - state.cameraAt < 2500 ? state.object : 0;
                state.objectAt = now;
            }
        }
        if (!document.hidden) {
            draw(now);
            if (now - state.lastHud > 150) { updateHud(now); state.lastHud = now; }
        }
        requestAnimationFrame(animate);
    }

    elements.pause.addEventListener('click', () => { state.paused = !state.paused; updateHud(performance.now()); });
    requestAnimationFrame(animate);
    return {
        bind(socket) {
            socket.on('connect', () => {
                state.connected = true;
                state.radarAt = state.brakeAt = state.cameraAt = 0;
                state.attack = null;
            });
            socket.on('disconnect', () => { state.connected = false; });
            socket.on('simulation_state', data => {
                if (data.running && state.running === false) {
                    state.speed = 65;
                    state.displayedDistance = 20;
                    state.sceneObject = 0;
                }
                state.running = data.running;
                state.defense = data.defense_enabled;
                state.attack = data.attack_mode;
                if (!data.running) {
                    state.radarAt = state.brakeAt = state.cameraAt = 0;
                    state.alert = null;
                    state.shieldUntil = 0;
                }
            });
            socket.on('new_message_batch', receiveMessages);
            socket.on('new_alert_batch', receiveAlerts);
            socket.on('system_log', receiveLog);
        },
    };
})();
