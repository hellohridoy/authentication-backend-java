package com.example.AuthenticationBackedJava.Authentication.service;

import com.example.AuthenticationBackedJava.Authentication.components.JwtUtil;
import com.example.AuthenticationBackedJava.Authentication.dto.LoginRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.LoginResponse;
import com.example.AuthenticationBackedJava.Authentication.dto.RegisterRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.social.SocialLoginRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.social.SocialUserInfo;
import com.example.AuthenticationBackedJava.Authentication.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final JwtBlacklistService jwtBlacklistService;

    public Map<String, Object> register(RegisterRequest registerRequest) {
        User user = userService.createUser(registerRequest);

        UserDetails userDetails = userService.loadUserByUsername(user.getUsername());
        String accessToken = jwtUtil.generateToken(userDetails, user.getId());
        String refreshToken = jwtUtil.generateRefreshToken(userDetails, user.getId());

        Map<String, Object> response = new HashMap<>();
        response.put("message", "User registered successfully");
        response.put("userId", user.getId());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("firstName", user.getFirstName());
        response.put("lastName", user.getLastName());
        response.put("roles", user.getRoleNames());
        response.put("access_token", accessToken);
        response.put("refresh_token", refreshToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", jwtUtil.getExpirationTime());
        response.put("refresh_expires_in", jwtUtil.getRefreshExpirationTime());

        log.info("User registered successfully: {}", user.getUsername());
        return response;
    }

    public LoginResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
            )
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userService.findByUsername(userDetails.getUsername());

        String accessToken = jwtUtil.generateToken(userDetails, user.getId());
        String refreshToken = jwtUtil.generateRefreshToken(userDetails, user.getId());

        LoginResponse response = new LoginResponse();
        response.setAccessToken(accessToken);
        response.setRefreshToken(refreshToken);
        response.setTokenType("Bearer");
        response.setExpiresIn(jwtUtil.getExpirationTime());
        response.setUserId(user.getId());
        response.setUsername(user.getUsername());
        response.setEmail(user.getEmail());
        response.setRoles(user.getRoleNames());

        log.info("User logged in successfully: {}", user.getUsername());
        return response;
    }

    public Map<String, String> logout(String token) {
        try {
            Claims claims = jwtUtil.extractAllClaims(token);
            String jti = claims.getId();
            Date expiration = claims.getExpiration();

            if (jti == null) {
                throw new IllegalArgumentException("Token does not contain JTI");
            }

            long currentTime = System.currentTimeMillis();
            long expirationTime = expiration.getTime();

            if (expirationTime > currentTime) {
                long remainingTimeInSeconds = (expirationTime - currentTime) / 1000;
                jwtBlacklistService.blacklistToken(jti, remainingTimeInSeconds);
                log.info("Token blacklisted successfully for logout: {}", jti);
                return Map.of("message", "Logout successful");
            } else {
                log.info("Token was already expired during logout: {}", jti);
                return Map.of("message", "Logout successful", "note", "Token was already expired");
            }
        } catch (ExpiredJwtException e) {
            log.info("Logout attempted with expired token");
            return Map.of("message", "Logout successful", "note", "Token was already expired");
        }
    }

    public Map<String, Object> refreshToken(String refreshToken) {
        String username = jwtUtil.extractUsername(refreshToken);

        if (username != null && jwtUtil.isTokenValid(refreshToken, userService.loadUserByUsername(username))) {
            UserDetails userDetails = userService.loadUserByUsername(username);
            User user = userService.findByUsername(username);

            String newAccessToken = jwtUtil.generateToken(userDetails, user.getId());

            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", newAccessToken);
            response.put("tokenType", "Bearer");
            response.put("expiresIn", jwtUtil.getExpirationTime());

            return response;
        } else {
            throw new IllegalArgumentException("Invalid refresh token");
        }
    }

    public Map<String, Object> getUserProfile(String token) {
        String username = jwtUtil.extractUsername(token);

        if (username != null) {
            User user = userService.findByUsername(username);

            Map<String, Object> profile = new HashMap<>();
            profile.put("userId", user.getId());
            profile.put("username", user.getUsername());
            profile.put("email", user.getEmail());
            profile.put("roles", user.getRoleNames());
            profile.put("createdAt", user.getCreatedAt());
            profile.put("updatedAt", user.getUpdatedAt());

            return profile;
        } else {
            throw new IllegalArgumentException("Invalid token");
        }
    }

    public Map<String, String> forgotPassword(String email) {
        if (!userService.existsByEmail(email)) {
            return Map.of("message", "If the email exists, a password reset link has been sent");
        }

        String resetToken = generatePasswordResetToken(email);
        log.info("Password reset requested for email: {}", email);
        // emailService.sendPasswordResetEmail(email, resetToken);  // TODO: wire up email service

        return Map.of("message", "If the email exists, a password reset link has been sent");
    }

    public Map<String, String> resetPassword(String token, String newPassword, String confirmPassword) {
        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("Passwords do not match");
        }

        String email = validatePasswordResetToken(token);
        if (email == null) {
            throw new IllegalArgumentException("Reset token is invalid or expired");
        }

        userService.resetPassword(email, newPassword);
        log.info("Password reset successful for email: {}", email);
        return Map.of("message", "Password has been reset successfully. You can now login with your new password.");
    }

    public Map<String, String> verifyEmail(String token, String email) {
        if (!validateEmailVerificationToken(token, email)) {
            throw new IllegalArgumentException("Verification token is invalid or expired");
        }

        User user = userService.findByEmail(email);
        if (user.getEmailVerified()) {
            return Map.of("message", "Email is already verified");
        }

        user.setEmailVerified(true);
        userService.updateUser(user.getId(), new RegisterRequest(
            user.getUsername(), user.getEmail(), null, user.getFirstName(), user.getLastName()
        ));

        log.info("Email verification successful for: {}", email);
        return Map.of("message", "Email has been verified successfully. You can now access all features.");
    }

    public Map<String, String> resendVerificationEmail(String email) {
        if (!userService.existsByEmail(email)) {
            return Map.of("message", "If the email exists, a new verification link has been sent");
        }

        User user = userService.findByEmail(email);
        if (user.getEmailVerified()) {
            return Map.of("message", "Email is already verified");
        }

        String verificationToken = generateEmailVerificationToken(email);
        log.info("Email verification resent for: {}", email);
        // emailService.sendVerificationEmail(email, verificationToken);  // TODO: wire up email service

        return Map.of("message", "If the email exists, a new verification link has been sent");
    }

    public Map<String, String> changePassword(String token, String currentPassword, String newPassword, String confirmPassword) {
        String username = jwtUtil.extractUsername(token);

        if (username == null) {
            throw new IllegalArgumentException("Invalid token");
        }

        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("New passwords do not match");
        }

        boolean success = userService.changePassword(username, currentPassword, newPassword);
        if (!success) {
            throw new IllegalArgumentException("Invalid current password");
        }

        log.info("Password changed successfully for user: {}", username);
        return Map.of("message", "Password has been changed successfully");
    }

    public Map<String, Object> socialLogin(SocialLoginRequest socialRequest) {
        log.info("Social login attempt with provider: {}", socialRequest.getProvider());

        SocialUserInfo socialUserInfo = validateSocialToken(socialRequest);
        if (socialUserInfo == null) {
            throw new IllegalArgumentException("Invalid social token");
        }

        User existingUser = null;
        boolean isNewUser = false;

        try {
            existingUser = userService.findByEmail(socialUserInfo.getEmail());
        } catch (Exception e) {
            isNewUser = true;
        }

        if (existingUser == null && socialUserInfo.getEmail() != null) {
            existingUser = createUserFromSocialInfo(socialUserInfo);
            isNewUser = true;
            log.info("Created new user from social login: {}", existingUser.getEmail());
        }

        if (existingUser == null) {
            throw new IllegalArgumentException("Unable to create user from social information");
        }

        UserDetails userDetails = userService.loadUserByUsername(existingUser.getUsername());
        String accessToken = jwtUtil.generateToken(userDetails, existingUser.getId());
        String refreshToken = jwtUtil.generateRefreshToken(userDetails, existingUser.getId());

        Map<String, Object> response = new HashMap<>();
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);
        response.put("tokenType", "Bearer");
        response.put("expiresIn", jwtUtil.getExpirationTime());
        response.put("userId", existingUser.getId());
        response.put("username", existingUser.getUsername());
        response.put("email", existingUser.getEmail());
        response.put("roles", existingUser.getRoleNames());
        response.put("isNewUser", isNewUser);
        response.put("provider", socialUserInfo.getProvider());
        response.put("socialUserInfo", socialUserInfo);

        log.info("Social login successful for user: {}", existingUser.getEmail());
        return response;
    }

    public Map<String, Object> getSupportedProviders() {
        Map<String, Object> providers = new HashMap<>();
        providers.put("google", Map.of("name", "Google", "enabled", true));
        providers.put("github", Map.of("name", "GitHub", "enabled", true));
        providers.put("facebook", Map.of("name", "Facebook", "enabled", true));
        return Map.of("providers", providers);
    }

    private SocialUserInfo validateSocialToken(SocialLoginRequest request) {
        try {
            return SocialUserInfo.builder()
                .providerId(request.getProviderId())
                .provider(request.getProvider())
                .email(request.getEmail())
                .name(request.getName())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .avatarUrl(request.getAvatarUrl())
                .username(generateUsernameFromEmail(request.getEmail()))
                .emailVerified(true)
                .build();
        } catch (Exception e) {
            log.error("Failed to validate social token", e);
            return null;
        }
    }

    private User createUserFromSocialInfo(SocialUserInfo socialInfo) {
        try {
            RegisterRequest registerRequest = new RegisterRequest();
            registerRequest.setEmail(socialInfo.getEmail());
            registerRequest.setUsername(generateUniqueUsername(socialInfo));
            registerRequest.setPassword(generateRandomPassword());
            registerRequest.setFirstName(socialInfo.getFirstName() != null ? socialInfo.getFirstName() : "");
            registerRequest.setLastName(socialInfo.getLastName() != null ? socialInfo.getLastName() : "");

            User user = userService.createUser(registerRequest);
            user.setEmailVerified(true);
            return user;
        } catch (Exception e) {
            log.error("Failed to create user from social info", e);
            throw new RuntimeException("Failed to create user from social information", e);
        }
    }

    private String generateUniqueUsername(SocialUserInfo socialInfo) {
        String baseUsername = socialInfo.getUsername();
        if (baseUsername == null || baseUsername.trim().isEmpty()) {
            baseUsername = generateUsernameFromEmail(socialInfo.getEmail());
        }

        String username = baseUsername;
        int counter = 1;
        while (userService.existsByUsername(username)) {
            username = baseUsername + counter;
            counter++;
        }
        return username;
    }

    private String generateUsernameFromEmail(String email) {
        if (email == null) return "user" + System.currentTimeMillis();

        String username = email.split("@")[0];
        username = username.replaceAll("[^a-zA-Z0-9]", "");

        if (username.length() < 3) {
            username = "user" + username;
        }
        return username.toLowerCase();
    }

    private String generateRandomPassword() {
        return java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    private String generatePasswordResetToken(String email) {
        return jwtUtil.generateToken(
            org.springframework.security.core.userdetails.User.withUsername(email)
                .password("")
                .authorities("ROLE_RESET")
                .build(),
            0L
        );
    }

    private String validatePasswordResetToken(String token) {
        try {
            Claims claims = jwtUtil.extractAllClaims(token);
            return claims.getSubject();
        } catch (Exception e) {
            log.warn("Invalid password reset token: {}", e.getMessage());
            return null;
        }
    }

    private String generateEmailVerificationToken(String email) {
        return jwtUtil.generateToken(
            org.springframework.security.core.userdetails.User.withUsername(email)
                .password("")
                .authorities("ROLE_VERIFY")
                .build(),
            0L
        );
    }

    private boolean validateEmailVerificationToken(String token, String email) {
        try {
            Claims claims = jwtUtil.extractAllClaims(token);
            return email.equals(claims.getSubject());
        } catch (Exception e) {
            log.warn("Invalid email verification token: {}", e.getMessage());
            return false;
        }
    }
}
