package com.hackathon.ops.config;

public record SimulatorConfig(
        String authServiceBaseUrl,
        String webhookUrl,
        int concurrentThreads,
        int floodDurationSeconds,
        int requestTimeoutSeconds
) {

    private static final String DEFAULT_AUTH_SERVICE = "http://localhost:8080";
    private static final String DEFAULT_WEBHOOK = "http://localhost:9000/webhook";
    private static final int DEFAULT_THREADS = 120;
    private static final int DEFAULT_FLOOD_SECONDS = 10;
    private static final int DEFAULT_TIMEOUT_SECONDS = 30;

    public static SimulatorConfig fromEnvironment() {
        return new SimulatorConfig(
                env("AUTH_SERVICE_BASE_URL", DEFAULT_AUTH_SERVICE),
                env("WEBHOOK_URL", DEFAULT_WEBHOOK),
                envInt("CONCURRENT_THREADS", DEFAULT_THREADS),
                envInt("FLOOD_DURATION_SECONDS", DEFAULT_FLOOD_SECONDS),
                envInt("REQUEST_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        );
    }

    public String chaosActivateUrl() {
        return authServiceBaseUrl + "/api/v1/admin/chaos/activate";
    }

    public String validateUrl() {
        return authServiceBaseUrl + "/api/v1/auth/validate";
    }

    private static String env(String key, String defaultValue) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return value.strip();
    }

    private static int envInt(String key, int defaultValue) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return Integer.parseInt(value.strip());
    }
}
