package com.hackathon.auth.exception;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String DATABASE_TIMEOUT_COUNTER = "auth.errors.database_timeout";

    private final Counter databaseTimeoutCounter;

    public GlobalExceptionHandler(MeterRegistry meterRegistry) {
        this.databaseTimeoutCounter = Counter.builder(DATABASE_TIMEOUT_COUNTER)
                .description("Count of database connection pool timeout errors")
                .register(meterRegistry);
    }

    @ExceptionHandler(DatabaseTimeoutException.class)
    public ResponseEntity<Map<String, Object>> handleDatabaseTimeout(DatabaseTimeoutException ex) {
        databaseTimeoutCounter.increment();
        log.error("Database timeout during auth validation: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "DATABASE_TIMEOUT",
                "message", ex.getMessage(),
                "timestamp", Instant.now().toString()
        ));
    }
}
