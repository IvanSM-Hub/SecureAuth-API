package com.ivansario.secureauth.exception;

public class UserProtectionException extends RuntimeException {

    public UserProtectionException(String message) {
        super(message);
    }

    public UserProtectionException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
    
}
