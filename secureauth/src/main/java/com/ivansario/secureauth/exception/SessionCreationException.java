package com.ivansario.secureauth.exception;

public class SessionCreationException extends RuntimeException {
    public SessionCreationException(String message) {
        super(message);
    }
    
    public SessionCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
