# SentinelGlobe Security Stack

Real Docker-based sensors. No emulated "up" state: each running entry below is
an upstream container that writes its own native logs.

## Containerised tools

| Tool | Compose service | Host ports | Native log |
| --- | --- | --- | --- |
| Suricata | `suricata` | host network (`eth0`) | `logs/suricata/eve.json` |
| Zeek | `zeek` | host network (`eth0`) | `logs/zeek/*.log` |
| Wazuh manager | `wazuh-manager` | 1514, 1515, 55000 | `logs/wazuh/alerts/alerts.json` |
| Fail2Ban | `fail2ban` | host network | `logs/fail2ban.log` |
| Cowrie | `cowrie` | 2222, 2223 | `logs/cowrie/cowrie.json` |
| OpenCanary | `opencanary` | 8081, 2225, 2121, 2323 | `logs/opencanary/opencanary.log` |
| HFish | `hfish` | 4433, 4434, 7879 | `logs/hfish/` |
| Conpot | `conpot` | 502, 102, 47808/udp, 161/udp, 623/udp, 8800 | `logs/conpot/conpot.json` |
| Beelzebub | `beelzebub` | 8082, 2224 | `logs/beelzebub/beelzebub.log` |

Security Onion and T-Pot are full operating-system appliances. They are listed
as `host-managed` and are not forced into a container.

Canarytokens is not a runnable single image and is not part of the stack.
SentinelGlobe's own canaries are real HTTP, DNS and file tokens served by the
application at `/api/security-stack/canaries`.

## Start

```bash
# configs are generated on server start and by POST /api/security-stack/configs
npm run dev
```

Then start tools from the Security Stack panel, or through the API with an
admin session. The manager runs `docker compose up -d --no-deps --force-recreate`
for the matching profile.

## Ingest

```bash
curl -X POST http://localhost:12001/api/security-stack/ingest/cowrie \
  -H "Authorization: Bearer $SENTINEL_STACK_INGEST_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @logs/cowrie/cowrie.json
```

NDJSON sources (Conpot, Beelzebub, Fail2Ban) use
`Content-Type: application/x-ndjson`.

## Host notes

- Docker must be reachable at `/var/run/docker.sock`.
- Suricata and Zeek capture the interface named by `SENTINEL_CAPTURE_IFACE`
  (default `eth0`) and need `NET_RAW`/`NET_ADMIN`.
- Suricata config is mounted at `/tmp/sentinel/suricata.yaml` because the image
  entrypoint recursively chowns `/etc/suricata` and aborts on read-only mounts.
- OpenCanary reads `/etc/opencanaryd/opencanary.conf`; the logger class must be
  `PyLogger` on current upstream images.
