# Security Onion appliance

Security Onion is a full Linux distribution, not a single container. Deploy it
on a dedicated host/VM with two NICs (management + sniffing), then forward its
Suricata/Zeek/Wazuh output to SentinelGlobe.

1. Install Security Onion from https://docs.securityonion.net/en/2.4/installation.html
2. Enable **Suricata**, **Zeek** and **Wazuh** in the SOC console.
3. Add a **Redis/Logstash HTTP output** or a small Filebeat/Vector shipper:

```yaml
output.http:
  url: "http://<sentinel-host>:12001/api/security-stack/ingest/security-onion"
  headers:
    x-sentinel-stack-token: "${SENTINEL_STACK_INGEST_TOKEN}"
  codec: ndjson
```

4. Verify with `curl -H "x-sentinel-stack-token: ..." .../api/security-stack`.

SentinelGlobe accepts Suricata eve.json, Zeek JSON and Wazuh alerts on that
single endpoint and normalizes all three.
