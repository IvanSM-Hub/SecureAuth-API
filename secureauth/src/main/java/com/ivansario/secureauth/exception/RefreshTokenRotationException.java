package com.ivansario.secureauth.exception;

public class RefreshTokenRotationException extends RuntimeException {
    public RefreshTokenRotationException(String message) {
        super(message);
    }

    public RefreshTokenRotationException(String message, Throwable cause) {
        super(message, cause);
    }
}
