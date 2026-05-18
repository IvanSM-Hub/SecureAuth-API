package com.ivansario.secureauth.exception;

public class InvalidConfirmationPasswordException extends RuntimeException {

    public InvalidConfirmationPasswordException(String message) {
        super(message);
    }

    public InvalidConfirmationPasswordException(String message, Throwable cause) {
        super(message, cause);
    }

}
