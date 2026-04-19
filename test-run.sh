#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# test-run.sh — full E2E test runner
#
# Usage:
#   ./test-run.sh                  # full suite
#   ./test-run.sh tests/e2e/groups/test_02_user_crud.py   # single group
#   HEADED=1 ./test-run.sh         # show browser window (useful for debugging)
#   SKIP_LDAP=1 ./test-run.sh      # skip LDAP/OIDC groups (faster)
# ---------------------------------------------------------------------------

set -euo pipefail

COMPOSE_FILE="docker-compose.test.yml"
PROJECT_NAME="tusshare_test"

# ---- Colours (no-op on dumb terminals) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${GREEN}[test-run]${NC} $*"; }
warn()  { echo -e "${YELLOW}[test-run]${NC} $*"; }
error() { echo -e "${RED}[test-run]${NC} $*"; }

# ---- Cleanup on exit ----
cleanup() {
    info "Tearing down test environment..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ---- Tear down any leftover state ----
info "Removing any previous test environment..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down -v --remove-orphans 2>/dev/null || true

# ---- Build the app image ----
info "Building application image..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" build app

# ---- Spin up environment ----
info "Starting test environment..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d

# ---- Wait for app to be healthy ----
info "Waiting for app to be healthy..."
MAX_WAIT=120
ELAPSED=0
until docker inspect --format='{{.State.Health.Status}}' "${PROJECT_NAME}_app" 2>/dev/null | grep -q "healthy"; do
    if [ $ELAPSED -ge $MAX_WAIT ]; then
        error "App did not become healthy within ${MAX_WAIT}s"
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs app
        exit 1
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
done
info "App is healthy."

# ---- Ensure test dependencies and Playwright browsers are installed ----
info "Installing test dependencies..."
pip install -r requirements-test.txt -q
python -m playwright install chromium --with-deps -q 2>/dev/null || python -m playwright install chromium

# ---- Determine which test arguments to pass ----
PYTEST_ARGS=("${@:-tests/e2e/}")

# Optional: skip LDAP/OIDC groups (they need external IdP health)
if [ "${SKIP_LDAP:-0}" = "1" ]; then
    PYTEST_ARGS+=("--ignore=tests/e2e/groups/test_09_ldap_integration.py")
    PYTEST_ARGS+=("--ignore=tests/e2e/groups/test_10_oidc_integration.py")
    warn "Skipping LDAP/OIDC groups (SKIP_LDAP=1)"
fi

# ---- Run the tests ----
info "Running test suite: ${PYTEST_ARGS[*]}"
export TEST_APP_URL="http://localhost:8001"
export TEST_HEADED="${HEADED:-0}"
export TEST_PROJECT_NAME="$PROJECT_NAME"

# pytest returns the number of failures as its exit code
set +e
python -m pytest "${PYTEST_ARGS[@]}" \
    --tb=short \
    -v \
    --no-header \
    -p no:warnings \
    -s
EXIT_CODE=$?
set -e

# ---- Report ----
if [ $EXIT_CODE -eq 0 ]; then
    info "All tests passed."
else
    error "Tests failed (exit code $EXIT_CODE)."
fi

exit $EXIT_CODE
