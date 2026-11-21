# T-Pot appliance

T-Pot is an all-in-one honeypot platform (20+ sensors + ELK). Install it on a
dedicated VM/host:

```bash
git clone https://github.com/telekom-security/tpotce
cd tpotce
./install.sh
```

After installation, ship its Cowrie/Suricata/ELK alerts to:

```
POST http://<sentinel-host>:12001/api/security-stack/ingest/t-pot
x-sentinel-stack-token: $SENTINEL_STACK_INGEST_TOKEN
Content-Type: application/x-ndjson
```

The endpoint auto-detects Cowrie JSON, Suricata eve.json and generic honeypot
JSON, so a single Logstash/Vector output is enough.
