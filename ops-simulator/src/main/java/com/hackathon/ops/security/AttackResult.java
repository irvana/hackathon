package com.hackathon.ops.security;

/**
 * Immutable result of a single attack vector test.
 *
 * @param vector         The attack vector that was tested.
 * @param httpStatus     HTTP status code returned by the Lambda / webhook receiver.
 * @param responseBody   Raw response body from the target.
 * @param durationMs     Round-trip time for the webhook POST in milliseconds.
 * @param detectedByLambda True when the response body contains a sanitization signal,
 *                         i.e. at least one [REDACTED_*] token or the word "sanitized".
 */
public record AttackResult(
        AttackVector vector,
        int          httpStatus,
        String       responseBody,
        long         durationMs,
        boolean      detectedByLambda
) {

    /** Friendly one-line summary for console output. */
    public String summary() {
        String status  = detectedByLambda ? "✅ SANITIZED" : "⚠️  PASSED THROUGH";
        return String.format(
                "  [%s] HTTP %-3d | %5d ms | %s",
                status, httpStatus, durationMs, vector.label()
        );
    }
}
