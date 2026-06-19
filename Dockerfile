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

# bcrypt → cffi → libffi; asyncpg → libpq; tusshare-opaque Rust .so → libgcc
RUN apk add --no-cache libffi libpq libgcc

# Install dependencies first (layer caching).
# Stage 1: verify each direct dependency against the committed wheel hash —
#   pip exits non-zero if any hash mismatches, failing the build immediately.
# Stage 2: resolve and install transitive deps; direct deps are already present
#   so only the missing transitive packages are fetched (no hash check for these).
COPY backend/requirements.txt backend/requirements-hashed.txt ./
RUN pip install --no-cache-dir --no-deps --require-hashes -r requirements-hashed.txt && \
    pip install --no-cache-dir -r requirements.txt

# Install the tusshare-opaque PyO3 wheel built in stage 1
COPY --from=rust-builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Copy application code
COPY backend/app ./app
COPY backend/entrypoint.sh ./entrypoint.sh
COPY frontend ./frontend-src

# Create data directories and non-root user
RUN mkdir -p /data/files /data/uploads \
    && addgroup -S tusshare && adduser -S -G tusshare -h /app tusshare \
    && chown -R tusshare:tusshare /app /data \
    && chmod +x /app/entrypoint.sh
USER tusshare

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=6 --start-period=30s \
    CMD wget -qO- http://127.0.0.1:8080/api/v1/health || exit 1

CMD ["/app/entrypoint.sh"]
