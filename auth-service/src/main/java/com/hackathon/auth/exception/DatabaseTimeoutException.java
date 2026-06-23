package com.hackathon.auth.exception;

public class DatabaseTimeoutException extends RuntimeException {

    public DatabaseTimeoutException(String message) {
        super(message);
    }

    public DatabaseTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
