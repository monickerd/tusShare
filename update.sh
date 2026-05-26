#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# update.sh — rebuild and redeploy the tusShare production stack
#
# Use this instead of a plain "docker compose up --build" after pulling new
# code.  The extra step is needed because the frontend volume
# (tusshare_frontend) is populated from the image only on first creation —
# Docker will not overwrite an existing volume on rebuild.  Removing it here
# forces Docker to repopulate it from the new image on the next "up".
#
# Usage:
#   ./update.sh              # rebuild image, refresh frontend volume, restart
#   ./update.sh --no-cache   # same, but with a clean Docker build cache
# ---------------------------------------------------------------------------

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[update]${NC} $*"; }
warn()  { echo -e "${YELLOW}[update]${NC} $*"; }
error() { echo -e "${RED}[update]${NC} $*"; }

BUILD_ARGS=()
if [[ "${1:-}" == "--no-cache" ]]; then
    BUILD_ARGS+=("--no-cache")
    info "Building with --no-cache"
fi

# ---- Bring the stack down (data volumes are NOT removed) ----
info "Stopping stack..."
docker compose down --remove-orphans

# ---- Rebuild the application image ----
info "Building application image..."
docker compose build "${BUILD_ARGS[@]}"

# ---- Remove the frontend volume so Docker repopulates it from the new image ----
FRONTEND_VOL="filexfer_tusshare_frontend"
if docker volume inspect "$FRONTEND_VOL" &>/dev/null; then
    info "Removing stale frontend volume ($FRONTEND_VOL)..."
    docker volume rm "$FRONTEND_VOL"
else
    info "Frontend volume not found — will be created fresh."
fi

# ---- Start the stack ----
info "Starting stack..."
docker compose up -d

# ---- Wait for the app to report healthy ----
info "Waiting for app to be healthy..."
MAX_WAIT=120
ELAPSED=0
until docker inspect --format='{{.State.Health.Status}}' tusshare 2>/dev/null | grep -q "healthy"; do
    if [[ $ELAPSED -ge $MAX_WAIT ]]; then
        error "App did not become healthy within ${MAX_WAIT}s — check logs:"
        docker compose logs tusshare --tail=50
        exit 1
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

info "Stack is healthy."
