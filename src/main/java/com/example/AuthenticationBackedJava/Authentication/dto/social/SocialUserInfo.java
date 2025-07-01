package com.example.AuthenticationBackedJava.Authentication.dto.social;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SocialUserInfo {
    private String providerId;
    private String provider;
    private String email;
    private String name;
    private String firstName;
    private String lastName;
    private String avatarUrl;
    private String username;
    private Boolean emailVerified;
}
