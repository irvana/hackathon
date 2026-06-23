graph TD
    %% Subgraph Environment Target & Simulator
    subgraph Local_or_Target_Env [1. Target App & Simulator Environment]
        A[ops-simulator <br> Java 17] -- 1. Trigger Chaos --> B(auth-service <br> Spring Boot 3.x)
        B -- 2. Push Metrics & Logs --> DD_Cloud[Datadog Platform]
        A -- 3. Fire Mock Webhook JSON --> C[AWS API Gateway]
    end

    %% Subgraph AWS Cloud (Orchestration)
    subgraph AWS_Cloud [2. Autonomous Agentic Layer]
        C --> D[AWS Lambda <br> Python 3.11 + ddtrace]
        
        subgraph Lambda_Internal [Lambda Processing Loop]
            D -- 4. Sanitize Input --> E[Sanitizer / Guardrail]
            E -- 5. Prompt with Tools --> F[Amazon Bedrock <br> Claude 3.x]
        end
    end

    %% Subgraph Model Context Protocol Bridge
    subgraph Datadog_Integration [3. Datadog MCP & Telemetry]
        F -- 6. Multi-Turn ReAct Loop --> G[Datadog MCP Server]
        G -- 7. Query Logs & Metrics --> DD_Cloud
        DD_Cloud -- 8. Return Telemetry Data --> G
        G --> F
    end

    %% Subgraph Outputs & Observability
    subgraph Outputs_and_Observability [4. Destinations & Monitoring]
        D -- 9. Stream Full Trace --> DD_LLM[Datadog LLM Observability]
        DD_LLM --> DD_Dash[Custom Datadog Dashboard]
        D -- 10. Post Incident Summary & Runbook --> H[Slack / Teams Channel]
    end

    %% Styling
    style Local_or_Target_Env fill:#f9f,stroke:#333,stroke-width:2px
    style AWS_Cloud fill:#bbf,stroke:#333,stroke-width:2px
    style Datadog_Integration fill:#dfd,stroke:#333,stroke-width:2px
    style Outputs_and_Observability fill:#fdd,stroke:#333,stroke-width:2px