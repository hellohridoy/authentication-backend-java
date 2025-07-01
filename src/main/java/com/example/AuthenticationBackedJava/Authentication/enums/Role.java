package com.example.AuthenticationBackedJava.Authentication.enums;

public enum Role {
    USER("Default role for users"),
    ADMIN("Administrator role with full access"),
    MODERATOR("Moderator role with limited admin access"),
    MANAGER("Manager role for business operations");

    private final String description;

    Role(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return this.name();
    }
}
