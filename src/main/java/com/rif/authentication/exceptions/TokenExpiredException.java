package com.rif.authentication.exceptions;

public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException() {
        super("Le token a expiré");
    }
}