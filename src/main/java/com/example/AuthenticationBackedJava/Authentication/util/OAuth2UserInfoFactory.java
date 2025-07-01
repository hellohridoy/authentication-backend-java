package com.example.AuthenticationBackedJava.Authentication.util;

import com.example.AuthenticationBackedJava.Authentication.entity.AuthProvider;

import com.example.AuthenticationBackedJava.Authentication.exceptions.ResourceNotFoundException;
import com.example.AuthenticationBackedJava.Authentication.util.OAuth2UserInfo;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        AuthProvider authProvider = AuthProvider.fromString(registrationId);

        switch (authProvider) {
            case GOOGLE:
                return new GoogleOAuth2UserInfo(attributes);
            case FACEBOOK:
                return new FacebookOAuth2UserInfo(attributes);
            case GITHUB:
                return new GithubOAuth2UserInfo(attributes);
            default:
                throw new ResourceNotFoundException.OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
