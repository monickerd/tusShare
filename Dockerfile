FROM python:3.12-alpine

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# bcrypt → cffi → libffi (runtime dep; not bundled in the musllinux wheel)
RUN apk add --no-cache libffi

# Install dependencies first (layer caching)
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/app ./app
COPY frontend ./frontend

# Create data directories
RUN mkdir -p /data/files /data/uploads

# Non-root user for security (Alpine uses BusyBox addgroup/adduser)
RUN addgroup -S tusshare && adduser -S -G tusshare -h /app tusshare \
    && chown -R tusshare:tusshare /app /data
USER tusshare

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/v1/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*"]
