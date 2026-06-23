#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

KEEP_RUNNING=false

usage() {
  cat <<'EOF'
Usage: ./run-scenario-docker.sh [options]

Runs the full hackathon drill entirely in Docker (no local Java required):
  1. Datadog Agent
  2. auth-service (with dd-java-agent)
  3. Mock webhook listener
  4. ops-simulator outage simulation

Options:
  --keep-running   Leave all containers running after the drill
  -h, --help       Show this help

Required:
  DD_API_KEY       Your Datadog API key

Optional:
  DD_SITE          Datadog site (default: datadoghq.com)
  DD_ENV           Environment tag (default: hackathon)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-running) KEEP_RUNNING=true; shift ;;
    -h|--help)      usage; exit 0 ;;
    *)              echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[[ -n "${DD_API_KEY:-}" ]] || { echo "ERROR: DD_API_KEY is required." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker is required." >&2; exit 1; }

echo "============================================================"
echo "  Hackathon Outage Drill — Docker"
echo "============================================================"
echo "  Datadog Agent : docker (datadog-agent)"
echo "  auth-service  : http://localhost:8080"
echo "  Webhook mock  : http://localhost:9000/webhook"
echo "  DD_ENV        : ${DD_ENV:-hackathon}"
echo "============================================================"
echo ""

if [[ "${KEEP_RUNNING}" == "true" ]]; then
  docker compose up --build -d datadog-agent webhook-mock auth-service
  docker compose run --rm --build ops-simulator
  echo ""
  echo "Drill complete. Containers still running. Stop with: docker compose down"
else
  docker compose up --build --exit-code-from ops-simulator --abort-on-container-exit
  docker compose down
  echo ""
  echo "Drill complete. All containers stopped."
fi
