package com.rif.authentication.exceptions;

public class InvalidPasswordFormatException extends RuntimeException {
    public InvalidPasswordFormatException() {
        super("Le mot de passe doit comporter au moins 12 caractères, inclure au moins une lettre majuscule, un chiffre et un caractère spécial.");
    }
}
