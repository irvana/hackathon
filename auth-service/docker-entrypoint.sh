#!/bin/sh
set -e

exec java \
  -javaagent:/app/dd-java-agent.jar \
  -Ddd.service="${DD_SERVICE:-auth-service}" \
  -Ddd.env="${DD_ENV:-hackathon}" \
  -Ddd.agent.host="${DD_AGENT_HOST:-datadog-agent}" \
  -Ddd.trace.agent.port="${DD_TRACE_AGENT_PORT:-8126}" \
  -jar /app/app.jar
