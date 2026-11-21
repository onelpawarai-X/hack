# HFish deployment

HFish is an enterprise honeypot fleet with a web console.

```bash
docker run -d --name sentinel-hfish \
  -p 4433:4433 -p 4434:4434 -p 7879:7879 \
  -v "$PWD/security-stack/logs/hfish:/opt/hfish/log" \
  dskyz/hfish:latest
```

Open `https://<host>:4433` to finish the console setup, then add this
webhook as an alert destination:

```
http://<sentinel-host>:12001/api/security-stack/ingest/hfish
```

Send the header `x-sentinel-stack-token: $SENTINEL_STACK_INGEST_TOKEN`.
