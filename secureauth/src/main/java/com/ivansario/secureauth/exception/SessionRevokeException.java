package com.ivansario.secureauth.exception;

public class SessionRevokeException extends RuntimeException {
    public SessionRevokeException(String message) {
        super(message);
    }
    
    public SessionRevokeException(String message, Throwable cause) {
        super(message, cause);
    }
}
