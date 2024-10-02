package com.rif.authentication.exceptions;

public class InvalidPasswordException extends RuntimeException{
    public InvalidPasswordException() {

        super("Mots de passe Incorrect");
    }
}
