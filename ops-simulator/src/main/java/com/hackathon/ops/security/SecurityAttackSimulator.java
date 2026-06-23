package com.hackathon.ops.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.hackathon.ops.config.SimulatorConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * SecurityAttackSimulator
 * =======================
 * Fires a series of malicious Datadog-style webhook payloads at the configured
 * webhook URL (the SRE Agent Lambda endpoint) and reports whether each attack
 * was detected / sanitized by the Lambda's guardrail layer.
 *
 * <p>Tested attack categories:
 * <ul>
 *   <li>Prompt Injection – credential exfiltration</li>
 *   <li>Prompt Injection – role hijacking</li>
 *   <li>Log Injection – SQL payloads</li>
 *   <li>Log Injection – command injection in tags</li>
 *   <li>Prompt Injection – unicode/homoglyph obfuscation</li>
 *   <li>PII Flood – bulk sensitive data in body</li>
 * </ul>
 *
 * <p>A result is marked "sanitized" when the Lambda response body contains at
 * least one {@code [REDACTED_*]} token or the word "sanitized" — the signals
 * written by the Python sanitize_payload() middleware in sre-agent-lambda.
 */
public class SecurityAttackSimulator {

    private static final String DETECTION_MARKER_REDACTED  = "[REDACTED";
    private static final String DETECTION_MARKER_SANITIZED = "sanitized";

    private final SimulatorConfig config;
    private final HttpClient      httpClient;
    private final ObjectMapper    objectMapper;

    public SecurityAttackSimulator(SimulatorConfig config) {
        this.config       = config;
        this.httpClient   = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.requestTimeoutSeconds()))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    // ------------------------------------------------------------------
    // Public entry point
    // ------------------------------------------------------------------

    /**
     * Run all attack vector tests sequentially and print a report.
     *
     * @return List of individual test results.
     */
    public List<AttackResult> runPromptInjectionTest() {
        printHeader();

        List<AttackResult> results = new ArrayList<>();

        for (AttackVector vector : AttackVector.values()) {
            System.out.printf("%n[ATTACK] Sending: %s%n", vector.label());

            AttackResult result = sendAttack(vector);
            results.add(result);

            System.out.println(result.summary());
            if (!result.detectedByLambda()) {
                System.out.println("         ⚠️  Lambda did NOT redact this payload. "
                        + "Review sanitize_payload() in sre-agent-lambda.");
            }
        }

        printReport(results);
        return results;
    }

    // ------------------------------------------------------------------
    // Internal – send a single attack vector
    // ------------------------------------------------------------------

    private AttackResult sendAttack(AttackVector vector) {
        String payload;
        try {
            payload = buildMaliciousPayload(vector);
        } catch (Exception e) {
            System.err.printf("  [ERROR] Failed to build payload for %s: %s%n",
                    vector.label(), e.getMessage());
            return new AttackResult(vector, 0, "", 0, false);
        }

        Instant before = Instant.now();
        int    httpStatus;
        String responseBody;

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.webhookUrl()))
                    .timeout(Duration.ofSeconds(config.requestTimeoutSeconds()))
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .header("Content-Type",  "application/json")
                    .header("Accept",        "application/json")
                    .header("User-Agent",    "Datadog/1.0")
                    .header("X-Attack-Test", "true")           // marker for logging
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString());

            httpStatus   = response.statusCode();
            responseBody = response.body() != null ? response.body() : "";

        } catch (Exception e) {
            long ms = Duration.between(before, Instant.now()).toMillis();
            System.err.printf("  [ERROR] HTTP request failed: %s%n", e.getMessage());
            return new AttackResult(vector, 0, e.getMessage(), ms, false);
        }

        long durationMs = Duration.between(before, Instant.now()).toMillis();
        boolean detected = isDetected(responseBody);

        return new AttackResult(vector, httpStatus, responseBody, durationMs, detected);
    }

    // ------------------------------------------------------------------
    // Payload construction
    // ------------------------------------------------------------------

    /**
     * Build a JSON webhook payload that mimics a Datadog Monitor alert but
     * injects malicious content into every text field.
     */
    private String buildMaliciousPayload(AttackVector vector) throws Exception {
        String alertId    = UUID.randomUUID().toString();
        String monitorUrl = "https://app.datadoghq.com/monitors/" + alertId;

        // Inject the attack string into the tags field as well
        String maliciousTags = "env:hackathon,service:auth-service,team:platform,"
                + "injected:" + vector.maliciousTitle().replace(",", ";");

        ObjectNode root = objectMapper.createObjectNode();
        root.put("id",           alertId);
        root.put("event_type",   "monitor");
        root.put("title",        vector.maliciousTitle());
        root.put("body",         buildMaliciousBody(vector));
        root.put("url",          monitorUrl);
        root.put("tags",         maliciousTags);
        root.put("alert_type",   "error");
        root.put("priority",     "normal");
        root.put("date_happened", Instant.now().getEpochSecond());
        root.put("source",       "Datadog");

        // Extra fields that a real Datadog webhook might include –
        // used here as additional injection surfaces
        root.put("last_updated", Instant.now().toString());
        root.put("org", "{\"id\":\"1\",\"name\":\"hackathon\"}");

        return objectMapper.writeValueAsString(root);
    }

    /**
     * Wrap the vector's raw malicious body in a realistic log-line envelope
     * so it looks like genuine structured output from the application.
     */
    private String buildMaliciousBody(AttackVector vector) {
        return String.format(
                "%s triggered on auth-service.%n"
                        + "Hackathon security drill — ATTACK VECTOR: %s%n%n"
                        + "--- BEGIN INJECTED CONTENT ---%n"
                        + "%s%n"
                        + "--- END INJECTED CONTENT ---%n%n"
                        + "Simulated log lines follow:%n"
                        + "  2024-01-01T00:00:00Z ERROR [auth-svc] %s%n"
                        + "  2024-01-01T00:00:01Z ERROR [auth-svc] "
                        + "Contact: attacker@evil.io  token=Bearer FAKETOKEN123%n"
                        + "  2024-01-01T00:00:02Z WARN  [auth-svc] "
                        + "Origin IP: 198.51.100.77  target_ip: 10.0.0.1%n",
                vector.maliciousTitle(),
                vector.name(),
                vector.maliciousBody(),
                vector.maliciousBody().lines().findFirst().orElse("")
        );
    }

    // ------------------------------------------------------------------
    // Detection heuristic
    // ------------------------------------------------------------------

    /**
     * Returns true when the Lambda response body shows evidence that the
     * sanitizer ran — it found and replaced at least one PII or injection
     * pattern with a [REDACTED_*] placeholder.
     */
    private boolean isDetected(String responseBody) {
        if (responseBody == null || responseBody.isBlank()) return false;
        String lower = responseBody.toLowerCase();
        return responseBody.contains(DETECTION_MARKER_REDACTED)
                || lower.contains(DETECTION_MARKER_SANITIZED);
    }

    // ------------------------------------------------------------------
    // Reporting
    // ------------------------------------------------------------------

    private void printHeader() {
        System.out.println();
        System.out.println("============================================================");
        System.out.println("  SecurityAttackSimulator — Prompt Injection & PII Test");
        System.out.println("============================================================");
        System.out.printf("  Target webhook : %s%n", config.webhookUrl());
        System.out.printf("  Attack vectors : %d%n", AttackVector.values().length);
        System.out.println("============================================================");
    }

    private void printReport(List<AttackResult> results) {
        long sanitized   = results.stream().filter(AttackResult::detectedByLambda).count();
        long passedThrough = results.size() - sanitized;

        System.out.println();
        System.out.println("============================================================");
        System.out.println("  SECURITY TEST REPORT");
        System.out.println("============================================================");
        System.out.printf("  Total vectors tested : %d%n", results.size());
        System.out.printf("  ✅ Sanitized          : %d%n", sanitized);
        System.out.printf("  ⚠️  Passed through     : %d%n", passedThrough);
        System.out.println("------------------------------------------------------------");

        results.forEach(r -> System.out.println(r.summary()));

        System.out.println("============================================================");

        if (passedThrough > 0) {
            System.out.println();
            System.out.println("  ACTION REQUIRED: " + passedThrough + " vector(s) were NOT sanitized.");
            System.out.println("  Review sanitize_payload() regex patterns in sre-agent-lambda/lambda_function.py");
            System.out.println("  and ensure _INJECTION_GUARD is present in all system prompts.");
        } else {
            System.out.println();
            System.out.println("  All attack vectors were sanitized by the Lambda guardrail. ✅");
        }

        System.out.println("============================================================");
    }
}
