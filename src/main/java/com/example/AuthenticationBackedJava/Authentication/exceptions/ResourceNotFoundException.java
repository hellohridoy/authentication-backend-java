package com.example.AuthenticationBackedJava.Authentication.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {

    private String resourceName;
    private String fieldName;
    private Object fieldValue;

    public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
        super(String.format("%s not found with %s : '%s'", resourceName, fieldName, fieldValue));
        this.resourceName = resourceName;
        this.fieldName = fieldName;
        this.fieldValue = fieldValue;
    }

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getResourceName() {
        return resourceName;
    }

    public String getFieldName() {
        return fieldName;
    }

    public Object getFieldValue() {
        return fieldValue;
    }

    // Email already exists exception
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public class EmailAlreadyExistsException extends RuntimeException {
        public EmailAlreadyExistsException(String message) {
            super(message);
        }
    }

    // Username already exists exception
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public class UsernameAlreadyExistsException extends RuntimeException {
        public UsernameAlreadyExistsException(String message) {
            super(message);
        }
    }

    // Invalid token exception
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public class InvalidTokenException extends RuntimeException {
        public InvalidTokenException(String message) {
            super(message);
        }
    }

    // Token expired exception
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public class TokenExpiredException extends RuntimeException {
        public TokenExpiredException(String message) {
            super(message);
        }
    }

    // Account not verified exception
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public class AccountNotVerifiedException extends RuntimeException {
        public AccountNotVerifiedException(String message) {
            super(message);
        }
    }

    // Account disabled exception
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public class AccountDisabledException extends RuntimeException {
        public AccountDisabledException(String message) {
            super(message);
        }
    }

    // OAuth2 authentication processing exception
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class OAuth2AuthenticationProcessingException extends RuntimeException {
        public OAuth2AuthenticationProcessingException(String message) {
            super(message);
        }

        public OAuth2AuthenticationProcessingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
