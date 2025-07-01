package com.example.AuthenticationBackedJava.Authentication.service;

import com.example.AuthenticationBackedJava.Authentication.entity.AuthProvider;
import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.enums.Role;
import com.example.AuthenticationBackedJava.Authentication.exceptions.ResourceNotFoundException;
import com.example.AuthenticationBackedJava.Authentication.repository.UserRepository;
import com.example.AuthenticationBackedJava.Authentication.util.OAuth2UserInfo;
import com.example.AuthenticationBackedJava.Authentication.util.OAuth2UserInfoFactory;
import com.example.AuthenticationBackedJava.Authentication.util.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger log = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        AuthProvider authProvider = AuthProvider.fromString(registrationId);

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
            registrationId, oAuth2User.getAttributes());

        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new ResourceNotFoundException.OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            if (!user.getProvider().equals(authProvider)) {
                throw new ResourceNotFoundException.OAuth2AuthenticationProcessingException(
                    "Looks like you're signed up with " + user.getProvider() +
                        " account. Please use your " + user.getProvider() + " account to login."
                );
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        User user = new User();

        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        AuthProvider provider = AuthProvider.fromString(registrationId);

        user.setProvider(provider);
        user.setProviderId(oAuth2UserInfo.getId());
        user.setUsername(generateUniqueUsername(oAuth2UserInfo));
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setEmailVerified(true); // OAuth2 emails are typically verified
        user.setFirstName(oAuth2UserInfo.getFirstName());
        user.setLastName(oAuth2UserInfo.getLastName());
        user.setImageUrl(oAuth2UserInfo.getImageUrl());

        // Set a random password (won't be used for OAuth2 users)
        user.setPassword(""); // OAuth2 users don't need password

        // Add default role
        user.addRole(Role.USER);

        // Set account status
        user.setIsEnabled(true);
        user.setIsAccountNonExpired(true);
        user.setIsAccountNonLocked(true);
        user.setIsCredentialsNonExpired(true);

        User savedUser = userRepository.save(user);
        log.info("New OAuth2 user registered: {} via {}", user.getEmail(), provider);

        return savedUser;
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setFirstName(oAuth2UserInfo.getFirstName());
        existingUser.setLastName(oAuth2UserInfo.getLastName());
        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());

        User updatedUser = userRepository.save(existingUser);
        log.info("Existing OAuth2 user updated: {}", existingUser.getEmail());

        return updatedUser;
    }

    private String generateUniqueUsername(OAuth2UserInfo oAuth2UserInfo) {
        String baseUsername = oAuth2UserInfo.getFirstName().toLowerCase();
        String username = baseUsername;
        int counter = 1;

        while (userRepository.existsByUsername(username)) {
            username = baseUsername + counter;
            counter++;
        }

        return username;
    }
}
