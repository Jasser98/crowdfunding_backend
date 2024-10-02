package com.rif.authentication.exceptions;

public class AuthenticationFailedException extends RuntimeException {
    public AuthenticationFailedException(String message) {
        super("Échec de l'authentification: " + message);
    }
}
