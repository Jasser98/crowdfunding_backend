package com.rif.authentication.exceptions;

public class TokenNotFoundException extends RuntimeException{

    public TokenNotFoundException() {
        super("Token invalide ou expiré");
    }
}
