package com.example.AuthenticationBackedJava.Authentication.validation;

import org.springframework.stereotype.Component;

@Component
public class PasswordValidator {

    private static final String UPPERCASE = ".*[A-Z].*";
    private static final String LOWERCASE = ".*[a-z].*";
    private static final String DIGIT     = ".*\\d.*";
    private static final String SPECIAL   = ".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*";
    private static final int    MIN_LENGTH = 8;

    public void validate(String password) {
        if (password == null || password.length() < MIN_LENGTH
                || !password.matches(UPPERCASE)
                || !password.matches(LOWERCASE)
                || !password.matches(DIGIT)
                || !password.matches(SPECIAL)) {
            throw new PasswordValidationException(
                "Password must be at least 8 characters and include uppercase, lowercase, digit, and special character"
            );
        }
    }

    public static class PasswordValidationException extends RuntimeException {
        public PasswordValidationException(String message) {
            super(message);
        }
    }
}
