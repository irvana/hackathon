#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_DIR="${ROOT_DIR}/auth-service"
OPS_DIR="${ROOT_DIR}/ops-simulator"
LOG_DIR="${ROOT_DIR}/.run-logs"

AUTH_JAR="${AUTH_DIR}/target/auth-service-1.0.0-SNAPSHOT.jar"
AGENT_JAR="${AUTH_DIR}/target/dd-java-agent.jar"
OPS_JAR="${OPS_DIR}/target/ops-simulator-1.0.0-SNAPSHOT.jar"

AUTH_PORT="${AUTH_PORT:-8080}"
WEBHOOK_PORT="${WEBHOOK_PORT:-9000}"
DD_AGENT_HOST="${DD_AGENT_HOST:-localhost}"

SKIP_AGENT=false
SKIP_BUILD=false
KEEP_RUNNING=false

usage() {
  cat <<'EOF'
Usage: ./run-scenario.sh [options]

Runs the full hackathon drill:
  1. Datadog Agent (docker compose)
  2. auth-service (with dd-java-agent)
  3. Mock webhook listener
  4. ops-simulator outage simulation

Options:
  --skip-agent     Skip Datadog Agent startup (local run without Docker)
  --skip-build     Skip Maven build (use existing JARs)
  --keep-running   Do not stop auth-service/webhook after the drill
  -h, --help       Show this help

Required for Datadog Agent:
  DD_API_KEY       Your Datadog API key

Optional:
  DD_SITE          Datadog site (default: datadoghq.com)
  DD_ENV           Environment tag (default: hackathon)
  WEBHOOK_URL      Webhook target (default: http://localhost:9000/webhook)
  JAVA_HOME        Java 17 home (auto-detected on macOS if unset)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-agent)   SKIP_AGENT=true; shift ;;
    --skip-build)   SKIP_BUILD=true; shift ;;
    --keep-running) KEEP_RUNNING=true; shift ;;
    -h|--help)      usage; exit 0 ;;
    *)              echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

log()  { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

detect_java_home() {
  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
    return
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && command -v /usr/libexec/java_home >/dev/null 2>&1; then
    JAVA_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
    export JAVA_HOME
  fi
  [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]] || fail "JAVA_HOME not set. Install Java 17 or export JAVA_HOME."
}

wait_for_url() {
  local url="$1"
  local label="$2"
  local attempts="${3:-60}"
  for ((i = 1; i <= attempts; i++)); do
    if curl -sf "$url" >/dev/null 2>&1; then
      log "${label} is ready"
      return 0
    fi
    sleep 1
  done
  fail "${label} did not become ready: ${url}"
}

build_projects() {
  log "Building auth-service and ops-simulator..."
  (cd "${AUTH_DIR}" && mvn -q clean package -DskipTests)
  (cd "${OPS_DIR}" && mvn -q clean package -DskipTests)
}

AUTH_PID=""
WEBHOOK_PID=""

cleanup() {
  local exit_code=$?
  if [[ "${KEEP_RUNNING}" == "true" ]]; then
    log "Leaving services running (--keep-running). Logs: ${LOG_DIR}"
    exit "${exit_code}"
  fi

  log "Stopping background services..."
  [[ -n "${AUTH_PID}" ]] && kill "${AUTH_PID}" 2>/dev/null || true
  [[ -n "${WEBHOOK_PID}" ]] && kill "${WEBHOOK_PID}" 2>/dev/null || true
  pkill -f "auth-service-1.0.0-SNAPSHOT.jar" 2>/dev/null || true

  if [[ "${SKIP_AGENT}" == "false" ]]; then
    (cd "${ROOT_DIR}" && docker compose down >/dev/null 2>&1 || true)
  fi

  exit "${exit_code}"
}

trap cleanup EXIT INT TERM

mkdir -p "${LOG_DIR}"
detect_java_home

if [[ "${SKIP_BUILD}" == "false" ]]; then
  build_projects
else
  [[ -f "${AUTH_JAR}" ]] || fail "Missing ${AUTH_JAR}. Run without --skip-build."
  [[ -f "${AGENT_JAR}" ]] || fail "Missing ${AGENT_JAR}. Run without --skip-build."
  [[ -f "${OPS_JAR}" ]]  || fail "Missing ${OPS_JAR}. Run without --skip-build."
fi

echo "============================================================"
echo "  Hackathon Outage Drill — full scenario"
echo "============================================================"
echo "  Datadog Agent : $([[ "${SKIP_AGENT}" == "true" ]] && echo 'skipped' || echo 'docker compose')"
echo "  auth-service  : http://localhost:${AUTH_PORT}"
echo "  Webhook mock  : http://localhost:${WEBHOOK_PORT}/webhook"
echo "  Logs          : ${LOG_DIR}"
echo "============================================================"

if [[ "${SKIP_AGENT}" == "false" ]]; then
  [[ -n "${DD_API_KEY:-}" ]] || fail "DD_API_KEY is required. Export it or use --skip-agent."
  command -v docker >/dev/null 2>&1 || fail "Docker is required to run the Datadog Agent."

  log "Starting Datadog Agent..."
  (cd "${ROOT_DIR}" && docker compose up -d)
  sleep 3
  docker ps --filter name=datadog-agent --format '{{.Names}}: {{.Status}}' || fail "Datadog Agent container failed to start"
else
  log "Skipping Datadog Agent (--skip-agent)"
fi

log "Starting mock webhook listener on :${WEBHOOK_PORT}..."
python3 -u -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        print('=== WEBHOOK RECEIVED ===', flush=True)
        print(body, flush=True)
        print('========================', flush=True)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, *_):
        pass

port = int(os.environ.get('WEBHOOK_PORT', '${WEBHOOK_PORT}'))
print(f'Webhook listener ready on http://localhost:{port}/webhook', flush=True)
HTTPServer(('localhost', port), Handler).serve_forever()
" >"${LOG_DIR}/webhook.log" 2>&1 &
WEBHOOK_PID=$!

log "Starting auth-service with Datadog Java agent..."
export DD_AGENT_HOST="${DD_AGENT_HOST}"
export DD_ENV="${DD_ENV:-hackathon}"
export DD_SERVICE="${DD_SERVICE:-auth-service}"
export DD_AGENT_METRICS_ENABLED="${DD_AGENT_METRICS_ENABLED:-true}"

"${JAVA_HOME}/bin/java" \
  -javaagent:"${AGENT_JAR}" \
  -Ddd.service="${DD_SERVICE}" \
  -Ddd.env="${DD_ENV}" \
  -Ddd.agent.host="${DD_AGENT_HOST}" \
  -Ddd.trace.agent.port="${DD_TRACE_AGENT_PORT:-8126}" \
  -jar "${AUTH_JAR}" >"${LOG_DIR}/auth-service.log" 2>&1 &
AUTH_PID=$!

wait_for_url "http://localhost:${AUTH_PORT}/actuator/health" "auth-service"

log "Smoke test — normal validate (expect HTTP 200, < 50ms)..."
curl -s -w "HTTP %{http_code} in %{time_total}s\n" \
  "http://localhost:${AUTH_PORT}/api/v1/auth/validate" -o /dev/null

log "Running ops-simulator..."
export WEBHOOK_URL="${WEBHOOK_URL:-http://localhost:${WEBHOOK_PORT}/webhook}"
export AUTH_SERVICE_BASE_URL="${AUTH_SERVICE_BASE_URL:-http://localhost:${AUTH_PORT}}"

"${JAVA_HOME}/bin/java" -jar "${OPS_JAR}" | tee "${LOG_DIR}/ops-simulator.log"

log "Post-drill — deactivating chaos and verifying recovery..."
curl -sf -X POST "http://localhost:${AUTH_PORT}/api/v1/admin/chaos/deactivate" >/dev/null
curl -s -w "HTTP %{http_code} in %{time_total}s\n" \
  "http://localhost:${AUTH_PORT}/api/v1/auth/validate" -o /dev/null

log "Custom error metric:"
curl -s "http://localhost:${AUTH_PORT}/actuator/metrics/auth.errors.database_timeout" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"  auth.errors.database_timeout = {d['measurements'][0]['value']}\")" \
  2>/dev/null || true

echo ""
echo "============================================================"
echo "  Scenario complete"
echo "============================================================"
echo "  auth-service log : ${LOG_DIR}/auth-service.log"
echo "  webhook log      : ${LOG_DIR}/webhook.log"
echo "  simulator log    : ${LOG_DIR}/ops-simulator.log"
if [[ "${SKIP_AGENT}" == "false" ]]; then
  echo "  Datadog Agent    : running (docker compose)"
  echo "  Check Datadog    : service:auth-service, env:${DD_ENV:-hackathon}"
fi
echo "============================================================"
