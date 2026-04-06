# ---------------------------------------------------------------------------
# Stage 1: Build the tusshare-opaque PyO3 wheel
# ---------------------------------------------------------------------------
FROM python:3.12-alpine AS rust-builder

# build-base: gcc/musl-dev needed by maturin for the cdylib link step
# curl: rustup installer
RUN apk add --no-cache build-base curl

# Install Rust stable via rustup (musl target is implicit on Alpine)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:$PATH"

# maturin builds the PyO3 extension wheel
RUN pip install --no-cache-dir "maturin>=1.5,<2"

WORKDIR /tusshare-opaque
COPY tusshare-opaque/ .

# Build a release wheel targeting the current platform (linux/musl)
RUN maturin build --release --out /dist --manylinux off

# ---------------------------------------------------------------------------
# Stage 2: Runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-alpine

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# bcrypt → cffi → libffi; asyncpg → libpq (PostgreSQL client library)
RUN apk add --no-cache libffi libpq

# Install dependencies first (layer caching)
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install the tusshare-opaque PyO3 wheel built in stage 1
COPY --from=rust-builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

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
