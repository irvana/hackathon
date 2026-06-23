package com.hackathon.ops.webhook;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.hackathon.ops.config.SimulatorConfig;
import com.hackathon.ops.traffic.TrafficStats;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

public class DatadogWebhookSimulator {

    private static final String MONITOR_TITLE = " [ALERT] auth-service HTTP 5xx error rate spiked";

    private final SimulatorConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public DatadogWebhookSimulator(SimulatorConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.requestTimeoutSeconds()))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    public int sendAlert(TrafficStats stats) throws Exception {
        String payload = buildPayload(stats);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.webhookUrl()))
                .timeout(Duration.ofSeconds(config.requestTimeoutSeconds()))
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", "Datadog/1.0")
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode();
    }

    private String buildPayload(TrafficStats stats) throws Exception {
        String alertId = UUID.randomUUID().toString();
        String monitorUrl = "https://app.datadoghq.com/monitors/" + alertId;
        String tags = "env:hackathon,service:auth-service,team:platform";

        double errorRate = stats.totalRequests() == 0
                ? 0.0
                : (stats.errorCount() * 100.0) / stats.totalRequests();

        String body = String.format(
                "%s triggered on auth-service.%n" +
                "HTTP 5xx error rate spiked during hackathon drill.%n%n" +
                "Total requests : %d%n" +
                "HTTP 5xx/errors: %d%n" +
                "Error rate     : %.1f%%%n" +
                "Triggered at   : %s",
                MONITOR_TITLE,
                stats.totalRequests(),
                stats.errorCount(),
                errorRate,
                Instant.now()
        );

        ObjectNode root = objectMapper.createObjectNode();
        root.put("id", alertId);
        root.put("event_type", "monitor");
        root.put("title", MONITOR_TITLE);
        root.put("body", body);
        root.put("url", monitorUrl);
        root.put("tags", tags);
        root.put("alert_type", "error");
        root.put("priority", "normal");
        root.put("date_happened", Instant.now().getEpochSecond());
        root.put("source", "Datadog");

        return objectMapper.writeValueAsString(root);
    }
}
