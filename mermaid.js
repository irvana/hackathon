graph TD
    %% Target Apps
    subgraph Target_Environment [1. Target App Environment]
        A[ops-simulator <br> Java 17] -- Trigger Chaos --> B(auth-service <br> Spring Boot 3.x)
        B -- Kirim Logs & Metrics --> DD_Cloud[Datadog Cloud Platform]
    end

    %% Webhook Trigger
    DD_Cloud -- Trigger Alert Webhook --> ECS_Task

    %% Single Container Boundary
    subgraph ECS_Task [2. AWS ECS Task / Docker Container Terpadu]
        subgraph Python_App [Python FastAPI Orchestrator Process]
            C[FastAPI <br> Endpoint /webhook] 
            D[ddtrace Wrapper <br> Tracing Layer]
            E[Amazon Bedrock <br> Claude 3.x Client]
        end

        subgraph MCP_Subprocess [Internal Subprocess Layer]
            F[Datadog MCP Server <br> Driven by npx Node.js]
        end

        %% Internal Communication
        C --> D
        D --> E
        E <=>|Stdio Transport <br> stdin / stdout| F
    end

    %% Datadog & Cloud Interactions
    F ==>|API Calls via Internet| DD_Cloud
    D ==>|Kirim Spans & Tokens| DD_LLM[Datadog LLM Observability]
    C ==>|Kirim RCA & Runbook| Slack[Slack Channel / Teams]

    %% Styling
    style Target_Environment fill:#fdf,stroke:#333,stroke-width:2px
    style ECS_Task fill:#bbf,stroke:#333,stroke-width:2px,stroke-dasharray: 5 5
    style Python_App fill:#fff,stroke:#333,stroke-width:1px
    style MCP_Subprocess fill:#dfd,stroke:#333,stroke-width:1px