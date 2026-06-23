package com.hackathon.ops.traffic;

import com.hackathon.ops.config.SimulatorConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class TrafficGenerator {

    private final SimulatorConfig config;

    public TrafficGenerator(SimulatorConfig config) {
        this.config = config;
    }

    public TrafficStats flood() throws InterruptedException {
        AtomicLong totalRequests = new AtomicLong();
        AtomicLong successCount = new AtomicLong();
        AtomicLong errorCount = new AtomicLong();
        AtomicLong transportFailures = new AtomicLong();

        Instant deadline = Instant.now().plusSeconds(config.floodDurationSeconds());
        ExecutorService workers = Executors.newFixedThreadPool(config.concurrentThreads());

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.validateUrl()))
                .timeout(Duration.ofSeconds(config.requestTimeoutSeconds()))
                .GET()
                .header("Accept", "application/json")
                .build();

        try {
            for (int i = 0; i < config.concurrentThreads(); i++) {
                workers.submit(() -> runWorker(
                        client,
                        request,
                        deadline,
                        totalRequests,
                        successCount,
                        errorCount,
                        transportFailures
                ));
            }

            workers.shutdown();
            if (!workers.awaitTermination(config.floodDurationSeconds() + config.requestTimeoutSeconds() + 15L,
                    TimeUnit.SECONDS)) {
                workers.shutdownNow();
            }
        } finally {
            if (!workers.isTerminated()) {
                workers.shutdownNow();
            }
        }

        return new TrafficStats(
                totalRequests.get(),
                successCount.get(),
                errorCount.get(),
                transportFailures.get()
        );
    }

    private void runWorker(
            HttpClient client,
            HttpRequest request,
            Instant deadline,
            AtomicLong totalRequests,
            AtomicLong successCount,
            AtomicLong errorCount,
            AtomicLong transportFailures
    ) {
        while (Instant.now().isBefore(deadline)) {
            totalRequests.incrementAndGet();
            try {
                HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
                int status = response.statusCode();
                if (status >= 200 && status < 300) {
                    successCount.incrementAndGet();
                } else {
                    errorCount.incrementAndGet();
                }
            } catch (Exception ex) {
                transportFailures.incrementAndGet();
            }
        }
    }
}
