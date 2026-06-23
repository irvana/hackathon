package com.hackathon.ops.traffic;

import com.hackathon.ops.config.SimulatorConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class ChaosActivator {

    private final SimulatorConfig config;
    private final HttpClient httpClient;

    public ChaosActivator(SimulatorConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.requestTimeoutSeconds()))
                .build();
    }

    public void activate() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.chaosActivateUrl()))
                .timeout(Duration.ofSeconds(config.requestTimeoutSeconds()))
                .POST(HttpRequest.BodyPublishers.noBody())
                .header("Accept", "application/json")
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "Failed to activate chaos mode (HTTP " + response.statusCode() + "): " + response.body()
            );
        }
    }
}
