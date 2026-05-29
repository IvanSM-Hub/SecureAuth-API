package com.ivansario.secureauth.exception;

public class InvalidPasswordProvided extends RuntimeException {

    public InvalidPasswordProvided(String message) {
        super(message);
    }
    
    public InvalidPasswordProvided(String message, Throwable cause) {
        super(message, cause);
    }

}
