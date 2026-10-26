const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Exercise the live-event contract and HUD without a browser or external packages.
function simulation() {
    let now = 1000, nextFrame;
    const events = new Map();
    const elements = new Map();
    const context2d = new Proxy({ createLinearGradient: () => ({ addColorStop() {} }) }, {
        get(target, key) { return key in target ? target[key] : () => {}; },
    });
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            textContent: '', dataset: {}, attrs: {}, listeners: {},
            classList: { toggle() {} },
            setAttribute(name, value) { this.attrs[name] = value; },
            addEventListener(name, handler) { this.listeners[name] = handler; },
            getContext: () => context2d,
            parentElement: { getBoundingClientRect: () => ({ width: 360, height: 160 }) },
        });
        return elements.get(id);
    }
    const sandbox = vm.createContext({
        document: { getElementById: element, hidden: false },
        window: { devicePixelRatio: 1 },
        performance: { now: () => now },
        matchMedia: () => ({ matches: false }),
        ResizeObserver: class { constructor(callback) { this.callback = callback; } observe() { this.callback(); } },
        requestAnimationFrame(callback) { nextFrame = callback; },
        socket: { on: (event, handler) => events.set(event, handler) },
    });
    const source = fs.readFileSync(path.join(__dirname, '../frontend/static/road-simulation.js'), 'utf8');
    vm.runInContext(source, sandbox);
    vm.runInContext('roadSimulation.bind(socket)', sandbox);
    const emit = (name, data) => events.get(name)(data);
    function tick(ms = 200) {
        for (let elapsed = 0; elapsed < ms; elapsed += 50) { now += 50; nextFrame(now); }
    }
    function telemetry(brake = 0, distance = 1400) {
        emit('new_message_batch', [
            { sender_node: 'radar', can_id: '0x100', data: { distance_cm: distance, speed: -125 } },
            { sender_node: 'camera', can_id: '0x101', data: { obj_class: 1, confidence: 87 } },
            { sender_node: 'brake_ecu', can_id: '0x300', data: { brake_pct: brake } },
        ]);
    }
    emit('connect');
    return { emit, tick, telemetry, value: name => element(`road-${name}`).textContent, element };
}

test('maps radar centimetres, signed relative speed, camera and brake ECU telemetry', () => {
    const sim = simulation();
    sim.telemetry(); sim.tick();
    assert.equal(sim.value('distance'), '14.0');
    assert.equal(sim.value('brake'), 0);
    assert.equal(sim.value('speed'), 65);
    assert.equal(sim.value('status'), 'Normal cruise');
    assert.match(sim.value('detail'), /Vehicle 87% · relative speed -12.5 km\/h/);
});

test('emergency ECU braking slows the modeled vehicle to a stop', () => {
    const sim = simulation();
    sim.telemetry(100, 200); sim.tick(2400);
    assert.equal(sim.value('speed'), 0);
    assert.equal(sim.value('brake'), 100);
    assert.equal(sim.value('status'), 'Emergency braking');
});

test('warning brakes decelerate, then vehicle accelerates when ECU releases brakes', () => {
    const sim = simulation();
    sim.telemetry(30, 700); sim.tick(1000);
    const brakingSpeed = sim.value('speed');
    assert.ok(brakingSpeed < 65 && brakingSpeed > 0);
    assert.equal(sim.value('status'), 'Caution · braking');
    sim.telemetry(0); sim.tick(1000);
    assert.ok(sim.value('speed') > brakingSpeed);
});

test('spoof and echoed radar frames do not overwrite physical source telemetry or fabricate brakes', () => {
    const sim = simulation();
    sim.telemetry();
    sim.emit('system_log', { message: 'Attack started: spoof (rate=10 msg/s)' });
    sim.emit('new_message_batch', [
        { sender_node: 'adas_ecu', can_id: '0x100', data: { distance_cm: 200, speed: 0 } },
        { sender_node: 'attacker', can_id: '0x300', data: { brake_pct: 100 } },
    ]);
    sim.tick();
    assert.equal(sim.value('distance'), '14.0');
    assert.equal(sim.value('brake'), 0);
    assert.match(sim.value('detail'), /Spoof attempt/);
});

test('shows observed IDS actions and defense state from existing server events', () => {
    const sim = simulation();
    sim.telemetry();
    sim.emit('system_log', { message: 'Dashboard connected | Session: 1 | Defense: ON' });
    sim.emit('new_alert_batch', [{ alert_type: 'replay', action_taken: 'blocked', details: 'Sequence 5 <= 10' }]);
    sim.tick();
    assert.equal(sim.value('security'), 'IDS ON');
    assert.match(sim.value('detail'), /IDS: replay · blocked · Sequence 5 <= 10/);
});

test('stale telemetry and disconnect freeze motion and stop displaying live readings', () => {
    const sim = simulation();
    sim.telemetry(30); sim.tick(2800);
    assert.equal(sim.value('status'), 'Waiting for telemetry');
    assert.equal(sim.value('speed'), '—');
    sim.emit('disconnect'); sim.tick();
    assert.equal(sim.value('status'), 'Connection lost');
    sim.emit('connect'); sim.tick();
    assert.equal(sim.value('status'), 'Waiting for telemetry');
    sim.telemetry(); sim.tick();
    assert.equal(sim.value('status'), 'Normal cruise');
});

test('pause freezes modeled motion but keeps live telemetry readable', () => {
    const sim = simulation();
    sim.telemetry(); sim.tick();
    sim.element('road-pause').listeners.click();
    sim.telemetry(100, 300); sim.tick(1000);
    assert.equal(sim.value('speed'), 65);
    assert.equal(sim.value('brake'), 100);
    assert.equal(sim.value('distance'), '3.0');
    assert.equal(sim.value('pause'), 'Resume');
});

test('message controls hold the scene when stopped and resume on fresh telemetry', () => {
    const sim = simulation();
    sim.emit('simulation_state', { running: false, defense_enabled: false, attack_mode: null });
    sim.telemetry(100, 200); sim.tick();
    assert.equal(sim.value('status'), 'Messages stopped');
    assert.equal(sim.value('speed'), '—');
    assert.match(sim.value('detail'), /Press Start Messages/);
    sim.emit('simulation_state', { running: true, defense_enabled: false, attack_mode: null });
    sim.telemetry(0, 1400); sim.tick();
    assert.equal(sim.value('speed'), 65);
    assert.equal(sim.value('status'), 'Normal cruise');
    sim.emit('simulation_state', { running: false, defense_enabled: false, attack_mode: null });
    sim.tick();
    assert.equal(sim.value('status'), 'Messages stopped');
    assert.equal(sim.value('brake'), '—');
});
