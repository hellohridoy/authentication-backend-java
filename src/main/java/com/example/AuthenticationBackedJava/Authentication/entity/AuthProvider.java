package com.example.AuthenticationBackedJava.Authentication.entity;

public enum AuthProvider {
    LOCAL,
    GOOGLE,
    FACEBOOK,
    GITHUB,
    MICROSOFT;

    public static AuthProvider fromString(String provider) {
        try {
            return AuthProvider.valueOf(provider.toUpperCase());
        } catch (IllegalArgumentException e) {
            return LOCAL; // Default to local if provider not recognized
        }
    }
}
