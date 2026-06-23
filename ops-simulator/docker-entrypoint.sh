#!/bin/sh
set -e

AUTH_URL="${AUTH_SERVICE_BASE_URL:-http://auth-service:8080}"
MAX_ATTEMPTS=90

echo "Waiting for auth-service at ${AUTH_URL}..."
attempt=0
until wget -q -O /dev/null "${AUTH_URL}/actuator/health" 2>/dev/null; do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge "${MAX_ATTEMPTS}" ]; then
    echo "ERROR: auth-service did not become ready in time" >&2
    exit 1
  fi
  sleep 1
done
echo "auth-service is ready"

echo "Smoke test — normal validate..."
wget -q -O - "${AUTH_URL}/api/v1/auth/validate" >/dev/null

echo "Running ops-simulator..."
java -jar /app/ops-simulator.jar

echo "Post-drill — deactivating chaos and verifying recovery..."
wget -q -O - --post-data="" "${AUTH_URL}/api/v1/admin/chaos/deactivate" >/dev/null 2>&1 || true
wget -q -O - "${AUTH_URL}/api/v1/auth/validate" >/dev/null

echo "Scenario complete."
