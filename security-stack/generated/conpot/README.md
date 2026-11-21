# Conpot deployment

Run the ICS/SCADA decoy with the upstream image:

```bash
docker run --rm -it \
  --name sentinel-conpot \
  -p 502:502 -p 102:102 -p 47808:47808 \
  -v "$PWD/security-stack/generated/conpot/conpot.cfg:/etc/conpot/conpot.cfg:ro" \
  -v "$PWD/security-stack/logs/conpot:/var/log/conpot" \
  honeynet/conpot:latest
```

Conpot writes JSON events to `/var/log/conpot/conpot.json`. Ship them to
`POST /api/security-stack/ingest/conpot`.
