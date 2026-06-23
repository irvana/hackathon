package com.hackathon.ops;

import com.hackathon.ops.config.SimulatorConfig;
import com.hackathon.ops.security.SecurityAttackSimulator;
import com.hackathon.ops.traffic.ChaosActivator;
import com.hackathon.ops.traffic.TrafficGenerator;
import com.hackathon.ops.traffic.TrafficStats;
import com.hackathon.ops.webhook.DatadogWebhookSimulator;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

public class OpsSimulatorApplication {

    /**
     * Entry point.
     *
     * <p>Usage modes:
     * <pre>
     *   java -jar ops-simulator.jar                   # default: chaos + flood + webhook
     *   java -jar ops-simulator.jar --security-test   # security attack simulation only
     *   java -jar ops-simulator.jar --all             # chaos drill THEN security test
     * </pre>
     *
     * <p>The mode can also be set via the {@code SIMULATOR_MODE} environment variable:
     * {@code chaos} (default), {@code security}, or {@code all}.
     */
    public static void main(String[] args) throws Exception {
        SimulatorConfig config = SimulatorConfig.fromEnvironment();
        SimulatorMode   mode   = resolveMode(args, config);

        printBanner(config, mode);

        switch (mode) {
            case SECURITY -> runSecurityTest(config);
            case ALL      -> { runChaosDrill(config); runSecurityTest(config); }
            default       -> runChaosDrill(config);
        }
    }

    // ------------------------------------------------------------------
    // Mode resolution
    // ------------------------------------------------------------------

    private static SimulatorMode resolveMode(String[] args, SimulatorConfig config) {
        // CLI flag takes precedence over environment variable
        if (Arrays.asList(args).contains("--security-test")) return SimulatorMode.SECURITY;
        if (Arrays.asList(args).contains("--all"))           return SimulatorMode.ALL;

        String envMode = System.getenv("SIMULATOR_MODE");
        if (envMode != null) {
            return switch (envMode.trim().toLowerCase()) {
                case "security" -> SimulatorMode.SECURITY;
                case "all"      -> SimulatorMode.ALL;
                default         -> SimulatorMode.CHAOS;
            };
        }
        return SimulatorMode.CHAOS;
    }

    // ------------------------------------------------------------------
    // Chaos drill (original behaviour)
    // ------------------------------------------------------------------

    private static void runChaosDrill(SimulatorConfig config) throws Exception {
        Instant start = Instant.now();

        System.out.println("[1/3] Activating chaos mode on auth-service...");
        ChaosActivator chaosActivator = new ChaosActivator(config);
        chaosActivator.activate();
        System.out.println("      Chaos mode activated.\n");

        System.out.printf("[2/3] Flooding validate endpoint (%d threads for %ds)...%n",
                config.concurrentThreads(), config.floodDurationSeconds());
        TrafficGenerator trafficGenerator = new TrafficGenerator(config);
        TrafficStats stats = trafficGenerator.flood();
        printTrafficSummary(stats);

        System.out.println("[3/3] Sending Datadog monitor webhook alert...");
        DatadogWebhookSimulator webhookSimulator = new DatadogWebhookSimulator(config);
        int webhookStatus = webhookSimulator.sendAlert(stats);
        System.out.printf("      Webhook delivered (HTTP %d).%n%n", webhookStatus);

        Duration elapsed = Duration.between(start, Instant.now());
        System.out.printf("Outage simulation complete in %ds.%n", elapsed.toSeconds());
        System.out.println("Check Datadog / your webhook receiver for the routed alert.");
    }

    // ------------------------------------------------------------------
    // Security attack test (new behaviour)
    // ------------------------------------------------------------------

    private static void runSecurityTest(SimulatorConfig config) {
        SecurityAttackSimulator attacker = new SecurityAttackSimulator(config);
        attacker.runPromptInjectionTest();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static void printBanner(SimulatorConfig config, SimulatorMode mode) {
        System.out.println("============================================================");
        System.out.printf("  ops-simulator — mode: %s%n", mode.label());
        System.out.println("============================================================");
        System.out.printf("  Auth service : %s%n", config.authServiceBaseUrl());
        System.out.printf("  Webhook URL  : %s%n", config.webhookUrl());
        System.out.printf("  Concurrency  : %d threads%n", config.concurrentThreads());
        System.out.printf("  Flood window : %d seconds%n", config.floodDurationSeconds());
        System.out.println("============================================================\n");
    }

    private static void printTrafficSummary(TrafficStats stats) {
        System.out.printf("      Requests sent     : %d%n", stats.totalRequests());
        System.out.printf("      HTTP 2xx            : %d%n", stats.successCount());
        System.out.printf("      HTTP 5xx / errors   : %d%n", stats.errorCount());
        System.out.printf("      Transport failures  : %d%n%n", stats.transportFailures());
    }

    // ------------------------------------------------------------------
    // Mode enum (private – no need to expose outside this class)
    // ------------------------------------------------------------------

    private enum SimulatorMode {
        CHAOS("production outage & alert routing drill"),
        SECURITY("security attack simulation"),
        ALL("chaos drill + security attack simulation");

        private final String label;

        SimulatorMode(String label) { this.label = label; }

        public String label() { return label; }
    }
}
