import fs from 'node:fs';
import path from 'node:path';
import type {
  GeneratedSecurityFile,
  SecurityToolConfigBundle,
  SecurityToolId,
} from '../../src/types/securityStack.ts';
import { getSecurityTool } from './catalog.ts';

const ROOT = path.resolve(process.cwd(), 'security-stack');
const GENERATED = path.resolve(ROOT, 'generated');

function file(filePath: string, content: string): GeneratedSecurityFile {
  return { path: filePath, content };
}

function suricataFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/suricata/suricata.yaml',
      `%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[${process.env.SENTINEL_HOME_NET ?? '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'}]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
default-log-dir: /var/log/suricata/
stats:
  enabled: yes
  interval: 30
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - anomaly
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - flow
        - netflow
        - ssh
        - stats:
            totals: yes
            threads: no
            deltas: no
  - pcap-log:
      enabled: yes
      filename: sentinel.pcap
      limit: 100mb
      mode: normal
      use-stream-depth: no
      honor-pass-rules: no
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: suricata.log
default-rule-path: /tmp/sentinel
rule-files:
  - sentinel.rules
app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes
    dns:
      enabled: yes
    ssh:
      enabled: yes
`,
    ),
    file(
      'generated/suricata/sentinel.rules',
      `# SentinelGlobe high-signal local rules
alert http any any -> any any (msg:"SentinelGlobe path traversal attempt"; http.uri; content:"../"; sid:9000002; rev:1;)
alert http any any -> any any (msg:"SentinelGlobe SQL injection attempt"; http.uri; content:"union"; nocase; content:"select"; nocase; distance:0; sid:9000003; rev:1;)
alert http any any -> any any (msg:"SentinelGlobe command injection attempt"; http.uri; content:"/bin/sh"; nocase; sid:9000004; rev:1;)
alert ssh any any -> any any (msg:"SentinelGlobe SSH brute force candidate"; flow:to_server; threshold: type both, track by_src, count 8, seconds 60; sid:9000005; rev:1;)
alert tcp any any -> any 502 (msg:"SentinelGlobe Modbus write to decoy"; flow:to_server; content:"|00 00|"; depth:4; sid:9000006; rev:1;)
`,
    ),
  ];
}

function zeekFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/zeek/local.zeek',
      `# SentinelGlobe Zeek site policy
@load base/frameworks/notice
@load base/frameworks/notice/weird
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/http/detect-sql-injection
@load policy/protocols/conn/known-hosts
@load policy/protocols/ssl/validate-certs
@load policy/frameworks/files/hash-all-files

redef LogAscii::use_json = T;
redef Notice::emailed_types += {
  SSH::Password_Guessing,
  HTTP::SQL_Injection_Attacker,
};
redef Notice::ignored_types += {
  SSL::Invalid_Server_Cert,
};

event zeek_init() {
  print "SentinelGlobe Zeek sensor online";
}
`,
    ),
    file(
      'generated/zeek/site.zeek',
      `# Extra high-signal local policy
@load ./local.zeek

`,
    ),
  ];
}

function wazuhFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/wazuh/ossec.conf',
      `<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories check_all="yes" report_changes="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">/workspace/project/hack/server,/workspace/project/hack/src</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/random-seed</ignore>
  </syscheck>
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
  </rootcheck>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
    <label key="source">suricata</label>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/zeek/notice.log</location>
    <label key="source">zeek</label>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/cowrie/cowrie.json</location>
    <label key="source">cowrie</label>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/opencanary/opencanary.log</location>
    <label key="source">opencanary</label>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5710,5712,5763,100001</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
`,
    ),
    file(
      'generated/wazuh/local_rules.xml',
      `<group name="sentinelglobe,">
  <rule id="100001" level="12">
    <if_sid>5710,5712</if_sid>
    <description>SentinelGlobe: repeated SSH authentication failures</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>
  <rule id="100002" level="10" frequency="6" timeframe="120">
    <if_matched_sid>100001</if_matched_sid>
    <same_source_ip />
    <description>SentinelGlobe: SSH brute force threshold exceeded</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
  <rule id="100003" level="12">
    <decoded_as>json</decoded_as>
    <field name="eventid">^cowrie\\.command\\.input$</field>
    <description>SentinelGlobe: Cowrie attacker shell command</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
  <rule id="100004" level="10">
    <decoded_as>json</decoded_as>
    <field name="eventid">^cowrie\\.login\\.failed$</field>
    <description>SentinelGlobe: Cowrie credential attempt</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
`,
    ),
  ];
}

function fail2banFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/fail2ban/jail.local',
      `[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = auto
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log

[cowrie]
enabled = true
port = 2222,2223
filter = cowrie
logpath = /var/log/cowrie/cowrie.json
maxretry = 3
bantime = 86400

[suricata-fast]
enabled = true
filter = suricata-fast
logpath = /var/log/suricata/fast.log
maxretry = 1
bantime = 86400

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive]
bantime = 604800
findtime = 86400
maxretry = 3
`,
    ),
    file(
      'generated/fail2ban/filter.d/cowrie.conf',
      `[Definition]
failregex = ^.*"eventid":\\s*"cowrie\\.login\\.failed".*"src_ip":\\s*"<HOST>".*$
ignoreregex =
`,
    ),
    file(
      'generated/fail2ban/filter.d/suricata-fast.conf',
      `[Definition]
failregex = ^\\[\\*\\*\\] \\[[^]]+\\] <HOST>:\\d+ -> .*$
ignoreregex =
`,
    ),
  ];
}

function cowrieFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/cowrie/cowrie.cfg',
      `[honeypot]
hostname = sentinel-decoy
log_path = /cowrie/cowrie-git/var/log/cowrie
download_path = /cowrie/cowrie-git/var/lib/cowrie/downloads
state_path = /cowrie/cowrie-git/var/lib/cowrie
share_path = /cowrie/cowrie-git/share/cowrie
etc_path = /cowrie/cowrie-git/etc
txtcmds_path = /cowrie/cowrie-git/share/cowrie/txtcmds
sensor_name = sentinelglobe-cowrie
listen_endpoints = tcp:2222:interface=0.0.0.0

[ssh]
enabled = true
version = SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4
listen_endpoints = tcp:2222:interface=0.0.0.0
auth_class = UserDB
auth_class_parameters = /cowrie/cowrie-git/etc/userdb.txt

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = /cowrie/cowrie-git/var/log/cowrie/cowrie.json
epoch_timestamp = false

[output_textlog]
enabled = true
logfile = /cowrie/cowrie-git/var/log/cowrie/cowrie.log
`,
    ),
    file(
      'generated/cowrie/userdb.txt',
      `root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:admin:/home/admin:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
`,
    ),
  ];
}

function opencanaryFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/opencanary/opencanary.conf',
      JSON.stringify(
        {
          'device.name': 'sentinelglobe-opencanary',
          'device.node_id': 'sentinelglobe',
          'ftp.enabled': true,
          'ftp.port': 2121,
          'ftp.banner': '220 Sentinel FTP service ready',
          'http.enabled': true,
          'http.port': 8081,
          'http.banner': 'Apache/2.4.58 (Ubuntu)',
          'http.skin': 'nasLogin',
          'ssh.enabled': true,
          'ssh.port': 2225,
          'ssh.version': 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4',
          'telnet.enabled': true,
          'telnet.port': 2323,
          'telnet.banner': 'Ubuntu 24.04 LTS',
          'smb.enabled': false,
          'mysql.enabled': false,
          'logger': {
            class: 'PyLogger',
            kwargs: {
              formatters: { plain: { format: '%(message)s' } },
              handlers: {
                file: {
                  class: 'logging.FileHandler',
                  filename: '/var/log/opencanary/opencanary.log',
                },
              },
            },
          },
        },
        null,
        2,
      ) + '\n',
    ),
  ];
}

function conpotFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/conpot/conpot.cfg',
      `[common]
sensorid = sentinelglobe-conpot

[virtual_file_system]
data_fs_url = osfs:///tmp/conpot-data
fs_url = tar:///home/conpot/.local/lib/python3.6/site-packages/conpot-0.6.0-py3.6.egg/conpot/data.tar

[session]
timeout = 30

[daemon]
;user = conpot
;group = conpot

[json]
enabled = True
filename = /var/log/conpot/conpot.json

[sqlite]
enabled = False

[mysql]
enabled = False

[syslog]
enabled = False

[hpfriends]
enabled = False

[taxii]
enabled = False

[fetch_public_ip]
enabled = False

[change_mac_addr]
enabled = False
`,
    ),
    file(
      'generated/conpot/README.md',
      `# Conpot deployment

Run the ICS/SCADA decoy with the upstream image:

\`\`\`bash
docker run --rm -it \\
  --name sentinel-conpot \\
  -p 502:502 -p 102:102 -p 47808:47808 \\
  -v "$PWD/security-stack/generated/conpot/conpot.cfg:/etc/conpot/conpot.cfg:ro" \\
  -v "$PWD/security-stack/logs/conpot:/var/log/conpot" \\
  honeynet/conpot:latest
\`\`\`

Conpot writes JSON events to \`/var/log/conpot/conpot.json\`. Ship them to
\`POST /api/security-stack/ingest/conpot\`.
`,
    ),
  ];
}

function beelzebubFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/beelzebub/beelzebub.yaml',
      `core:
  logging:
    debug: false
    debugReportCaller: false
    logDisableTimestamp: false
    logsPath: /var/log/beelzebub/beelzebub.log
  tracings:
    rabbit-mq:
      enabled: false
      uri: ""
  prometheus:
    enabled: false
    path: "/metrics"
    port: ":2112"
  beelzebub-cloud:
    enabled: false
    uri: ""
    auth-token: ""
`,
    ),
    file(
      'generated/beelzebub/services/ssh-2224.yaml',
      `apiVersion: "v1"
protocol: "ssh"
address: ":2224"
description: "SentinelGlobe SSH deception"
commands:
  - regex: "^(.+)$"
    handler: "DecoyShell"
serverVersion: "OpenSSH_9.6p1"
serverName: "ubuntu"
passwordRegex: "^(root|admin|ubuntu|123456|password|toor)$"
deadlineTimeoutSeconds: 600
`,
    ),
    file(
      'generated/beelzebub/services/http-8082.yaml',
      `apiVersion: "v1"
protocol: "http"
address: ":8082"
description: "SentinelGlobe HTTP deception"
commands:
  - regex: ".*"
    handler: "Unauthorized"
    headers:
      - "www-Authenticate: Basic"
      - "server: Apache/2.4.58 (Ubuntu)"
    statusCode: 401
`,
    ),
  ];
}

function hfishFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'generated/hfish/README.md',
      `# HFish deployment

HFish is an enterprise honeypot fleet with a web console.

\`\`\`bash
docker run -d --name sentinel-hfish \\
  -p 4433:4433 -p 4434:4434 -p 7879:7879 \\
  -v "$PWD/security-stack/logs/hfish:/opt/hfish/log" \\
  dskyz/hfish:latest
\`\`\`

Open \`https://<host>:4433\` to finish the console setup, then add this
webhook as an alert destination:

\`\`\`
http://<sentinel-host>:12001/api/security-stack/ingest/hfish
\`\`\`

Send the header \`x-sentinel-stack-token: $SENTINEL_STACK_INGEST_TOKEN\`.
`,
    ),
  ];
}


function securityOnionFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'appliances/security-onion/README.md',
      `# Security Onion appliance

Security Onion is a full Linux distribution, not a single container. Deploy it
on a dedicated host/VM with two NICs (management + sniffing), then forward its
Suricata/Zeek/Wazuh output to SentinelGlobe.

1. Install Security Onion from https://docs.securityonion.net/en/2.4/installation.html
2. Enable **Suricata**, **Zeek** and **Wazuh** in the SOC console.
3. Add a **Redis/Logstash HTTP output** or a small Filebeat/Vector shipper:

\`\`\`yaml
output.http:
  url: "http://<sentinel-host>:12001/api/security-stack/ingest/security-onion"
  headers:
    x-sentinel-stack-token: "\${SENTINEL_STACK_INGEST_TOKEN}"
  codec: ndjson
\`\`\`

4. Verify with \`curl -H "x-sentinel-stack-token: ..." .../api/security-stack\`.

SentinelGlobe accepts Suricata eve.json, Zeek JSON and Wazuh alerts on that
single endpoint and normalizes all three.
`,
    ),
  ];
}

function tpotFiles(): GeneratedSecurityFile[] {
  return [
    file(
      'appliances/t-pot/README.md',
      `# T-Pot appliance

T-Pot is an all-in-one honeypot platform (20+ sensors + ELK). Install it on a
dedicated VM/host:

\`\`\`bash
git clone https://github.com/telekom-security/tpotce
cd tpotce
./install.sh
\`\`\`

After installation, ship its Cowrie/Suricata/ELK alerts to:

\`\`\`
POST http://<sentinel-host>:12001/api/security-stack/ingest/t-pot
x-sentinel-stack-token: $SENTINEL_STACK_INGEST_TOKEN
Content-Type: application/x-ndjson
\`\`\`

The endpoint auto-detects Cowrie JSON, Suricata eve.json and generic honeypot
JSON, so a single Logstash/Vector output is enough.
`,
    ),
  ];
}

const BUILDERS: Partial<Record<SecurityToolId, () => GeneratedSecurityFile[]>> = {
  suricata: suricataFiles,
  zeek: zeekFiles,
  wazuh: wazuhFiles,
  'security-onion': securityOnionFiles,
  fail2ban: fail2banFiles,
  cowrie: cowrieFiles,
  't-pot': tpotFiles,
  opencanary: opencanaryFiles,
  hfish: hfishFiles,
  conpot: conpotFiles,
  beelzebub: beelzebubFiles,
};

export function buildSecurityToolConfig(toolId: SecurityToolId): SecurityToolConfigBundle {
  const tool = getSecurityTool(toolId);
  if (!tool) throw new Error(`Unknown security tool: ${toolId}`);
  const builder = BUILDERS[toolId];
  if (!builder) throw new Error(`No config builder for: ${toolId}`);
  const files = builder();
  const deployCommands =
    tool.deployment === 'appliance'
      ? [`# Follow security-stack/${tool.configPath ?? 'appliances'} on a dedicated host`]
      : [
          `cd security-stack`,
          `docker compose --profile ${tool.profiles[0] ?? 'core'} up -d ${tool.composeService ?? tool.id}`,
        ];
  return {
    toolId,
    generatedAt: new Date().toISOString(),
    files,
    deployCommands,
    notes: [
      'Generated files are real upstream-format configuration, not placeholders.',
      'Privileged network sensors need NET_ADMIN/NET_RAW or host networking.',
      `Ship alerts to /api/security-stack/ingest/${tool.id} with x-sentinel-stack-token.`,
    ],
  };
}

export function writeSecurityToolConfigs(toolId?: SecurityToolId): string[] {
  const tools = toolId ? [toolId] : (Object.keys(BUILDERS) as SecurityToolId[]);
  const written: string[] = [];
  for (const id of tools) {
    const bundle = buildSecurityToolConfig(id);
    for (const generated of bundle.files) {
      const absolute = path.resolve(ROOT, generated.path.replace(/^security-stack\//, ''));
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      fs.writeFileSync(absolute, generated.content, 'utf8');
      written.push(path.relative(process.cwd(), absolute));
    }
  }
  fs.mkdirSync(path.resolve(ROOT, 'logs'), { recursive: true });
  return written;
}

export function getSecurityStackPaths() {
  return {
    root: ROOT,
    generated: GENERATED,
    composeFile: path.resolve(ROOT, 'docker-compose.yml'),
    logs: path.resolve(ROOT, 'logs'),
  };
}
