package com.rif.authentication.exceptions;

public class PasswordMismatchException extends RuntimeException {
    public PasswordMismatchException() {
        super("Les mots de passe ne correspondent pas");
    }
}