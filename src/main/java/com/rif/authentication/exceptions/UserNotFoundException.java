package com.rif.authentication.exceptions;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(Long id) {

        super("Utilisateur avec l'ID " + id + " n'est pas disponible");
    }

    public UserNotFoundException(String email) {
        super("Utilisateur avec l'email " + email + " n'est pas disponible");
    }
}
