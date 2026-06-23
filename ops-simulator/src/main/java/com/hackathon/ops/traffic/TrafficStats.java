package com.hackathon.ops.traffic;

public record TrafficStats(
        long totalRequests,
        long successCount,
        long errorCount,
        long transportFailures
) {
}
