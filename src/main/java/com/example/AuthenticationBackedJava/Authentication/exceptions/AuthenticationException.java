package com.example.AuthenticationBackedJava.Authentication.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

public class AuthenticationException extends RuntimeException {

    public AuthenticationException(String message) {
        super(message);
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class UserNotFoundException extends AuthenticationException {
        public UserNotFoundException(String message) {
            super(message);
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class WrongPasswordException extends AuthenticationException {
        public WrongPasswordException(String message) {
            super(message);
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class TokenExpiredException extends AuthenticationException {
        public TokenExpiredException(String message) {
            super(message);
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class InvalidTokenException extends AuthenticationException {
        public InvalidTokenException(String message) {
            super(message);
        }
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    public static class AccountLockedException extends AuthenticationException {
        public AccountLockedException(String message) {
            super(message);
        }
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    public static class AccountDisabledException extends AuthenticationException {
        public AccountDisabledException(String message) {
            super(message);
        }
    }
}

