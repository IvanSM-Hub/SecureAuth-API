package com.ivansario.secureauth.exception;

public class RefreshTokenRevokedException extends RuntimeException {
    public RefreshTokenRevokedException(String message) {
        super(message);
    }

    public RefreshTokenRevokedException(String message, Throwable cause) {
        super(message, cause);
    }
}
