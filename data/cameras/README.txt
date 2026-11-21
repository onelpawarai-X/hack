# SentinelGlobe public camera registry
# No camera API is called. Add only cameras that are explicitly public and
# whose terms allow viewing/embedding. Do not add private, residential or
# workplace cameras. Verify local privacy law before use.
#
# POST /api/cameras
# { "name":"...", "lat":0, "lon":0, "url":"https://...", "protocol":"hls|mjpeg|iframe|link",
#   "city":"...", "country":"...", "source":"...", "attribution":"..." }
