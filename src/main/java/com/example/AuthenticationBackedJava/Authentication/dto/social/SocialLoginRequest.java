package com.example.AuthenticationBackedJava.Authentication.dto.social;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SocialLoginRequest {
    @NotBlank(message = "Provider is required")
    private String provider; // "google", "github", "facebook"

    @NotBlank(message = "Access token is required")
    private String accessToken; // From frontend OAuth flow

    private String email;
    private String name;
    private String firstName;
    private String lastName;
    private String avatarUrl;
    private String providerId;
}
