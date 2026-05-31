#!/bin/sh
# Copy staged frontend files into the tmpfs mount on every container start.
# This ensures the running container always reflects the current image build
# without requiring named-volume management on the host.
cp -r /app/frontend-src/. /app/frontend/
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8080 \
    --proxy-headers \
    "--forwarded-allow-ips=*"
