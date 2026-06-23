# Technical Specification & Stack Constraints

## Target Stack
- **Target Apps**: Java 17, Spring Boot 3.x, Maven, Micrometer Datadog.
- **Orchestrator**: AWS Lambda (Python 3.11) + Amazon Bedrock (Claude 3.5 Sonnet / 3.7 Sonnet).
- **Integration Protocol**: Model Context Protocol (MCP) untuk menghubungkan Bedrock dengan Datadog MCP Server.
- **Observability**: Datadog LLM Observability & Datadog APM Tracing (`ddtrace`).

## Minimum Bar Checklist
- [ ] Minimal 1 AI Agent memanggil tool (`get_metrics`, `get_logs`) via Datadog MCP Server.
- [ ] Minimal 1 span Bedrock muncul di Datadog LLM Observability.
- [ ] Dashboard Datadog Custom dengan minimal 3 widget: System Health, Agent LLM Trace, dan Live Postmortem Markdown.