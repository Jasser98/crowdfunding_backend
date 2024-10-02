package com.rif.authentication.exceptions;

public class InvalidEmailException extends RuntimeException {
    public InvalidEmailException() {
        super("Format de l'email invalide");
    }
}