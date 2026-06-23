package com.hackathon.auth.service;

import com.hackathon.auth.exception.DatabaseTimeoutException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthValidationService {

    private static final long CHAOS_CPU_BURN_MS = 2_000L;
    private static final long CHAOS_SLEEP_MS = 5_000L;

    private final ChaosModeService chaosModeService;

    public Map<String, Object> validate() {
        if (chaosModeService.isChaosMode()) {
            log.warn("Chaos mode active — simulating database connection pool exhaustion");
            simulateDatabaseConnectionPoolTimeout();
        }

        return Map.of(
                "valid", true,
                "message", "Token validated successfully"
        );
    }

    private void simulateDatabaseConnectionPoolTimeout() {
        burnCpu();
        sleepQuietly(CHAOS_SLEEP_MS);
        throw new DatabaseTimeoutException(
                "Timed out waiting for connection from pool after " + CHAOS_SLEEP_MS + "ms"
        );
    }

    /**
     * Heavy computational loop that resists JIT dead-code elimination (Math.blackhole style).
     */
    private void burnCpu() {
        long deadline = System.nanoTime() + Duration.ofMillis(CHAOS_CPU_BURN_MS).toNanos();
        double accumulator = ThreadLocalRandom.current().nextDouble();

        while (System.nanoTime() < deadline) {
            for (int i = 0; i < 100_000; i++) {
                accumulator += Math.sin(i) * Math.cos(i);
                if (accumulator > 1_000_000) {
                    accumulator = ThreadLocalRandom.current().nextDouble();
                }
            }
        }

        if (accumulator == Double.NEGATIVE_INFINITY) {
            log.debug("Unreachable branch to prevent loop elimination: {}", accumulator);
        }
    }

    private void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new DatabaseTimeoutException("Interrupted while waiting for database connection", ex);
        }
    }
}
