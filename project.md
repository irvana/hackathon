# Product Specification: The Self-Healing Shadow (Autonomous SRE Copilot)

## Goal
Membangun AI Agent SRE yang berfungsi sebagai Tier-1 Responder. Ketika ada alert dari Datadog, agent secara otonom melakukan investigasi masalah, mencari akar penyebab (Root Cause Analysis), dan memberikan runbook perbaikan otomatis ke tim SRE di Slack.

## Core Features
1. **Target App Environment**: Aplikasi Java Spring Boot yang bisa disimulasikan error-nya.
2. **Ops Simulator**: Alat pembuat traffic chaos dan pengirim webhook tiruan mirip Datadog Monitor.
3. **Autonomous SRE Agent**: AWS Lambda bertenaga Amazon Bedrock yang bisa memanggil tool Datadog via MCP Server untuk triage alert.