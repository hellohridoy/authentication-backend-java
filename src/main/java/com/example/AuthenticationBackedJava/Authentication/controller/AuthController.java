package com.example.AuthenticationBackedJava.Authentication.controller;

import com.example.AuthenticationBackedJava.Authentication.components.JwtUtil;
import com.example.AuthenticationBackedJava.Authentication.dto.LoginRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.LoginResponse;
import com.example.AuthenticationBackedJava.Authentication.dto.RegisterRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.social.SocialLoginRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.social.SocialUserInfo;
import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.service.JwtBlacklistService;
import com.example.AuthenticationBackedJava.Authentication.service.UserService;
import com.example.AuthenticationBackedJava.Authentication.validation.PasswordValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Register, login, logout, token management, password reset, email verification, and social login")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;

    private final  UserService userService;

    private final  JwtUtil jwtUtil;

    private final  JwtBlacklistService jwtBlacklistService;

    @Operation(summary = "Register a new user", description = "Creates a new account and returns JWT tokens immediately")
    @PostMapping("/api/auth/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
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
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (PasswordValidator.PasswordValidationException e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Weak password", "message", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Registration failed", "message", e.getMessage()));
        } catch (Exception e) {
            log.error("Error during user registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Registration failed", "message", "An error occurred during registration"));
        }
    }

    @Operation(summary = "Login", description = "Authenticate with username and password, returns JWT tokens")
    @PostMapping("/api/auth/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
                )
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername());

            // Generate JWT token
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
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            log.warn("Login failed for user: {}", loginRequest.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials", "message", "Username or password is incorrect"));
        } catch (Exception e) {
            log.error("Error during login", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Login failed", "message", "An error occurred during login"));
        }
    }

    @Operation(summary = "Logout", description = "Invalidates the current access token by adding it to the blacklist")
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping("/api/auth/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            // Extract token from Authorization header
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid token format", "message", "Authorization header must start with 'Bearer '"));
            }

            String token = authHeader.substring(7);

            // Extract claims from token
            Claims claims = jwtUtil.extractAllClaims(token);
            String jti = claims.getId();
            Date expiration = claims.getExpiration();

            if (jti == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid token", "message", "Token does not contain JTI"));
            }

            // Calculate remaining time until token expires
            long currentTime = System.currentTimeMillis();
            long expirationTime = expiration.getTime();

            if (expirationTime > currentTime) {
                long remainingTimeInSeconds = (expirationTime - currentTime) / 1000;
                // Add the token to blacklist with the exact remaining time
                jwtBlacklistService.blacklistToken(jti, remainingTimeInSeconds);
                log.info("Token blacklisted successfully for logout: {}", jti);
            } else {
                // Token is already expired, no need to blacklist
                log.info("Token was already expired during logout: {}", jti);
                return ResponseEntity.ok(Map.of("message", "Logout successful", "note", "Token was already expired"));
            }

            return ResponseEntity.ok(Map.of("message", "Logout successful"));

        } catch (ExpiredJwtException e) {
            log.info("Logout attempted with expired token");
            return ResponseEntity.ok(Map.of("message", "Logout successful", "note", "Token was already expired"));
        } catch (Exception e) {
            log.error("Error during logout", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Logout failed", "message", e.getMessage()));
        }
    }

    @Operation(summary = "Refresh access token", description = "Exchange a valid refresh token for a new access token")
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping("/api/auth/refresh-token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid token format", "message", "Authorization header must start with 'Bearer '"));
            }

            String refreshToken = authHeader.substring(7);
            String username = jwtUtil.extractUsername(refreshToken);

            if (username != null && jwtUtil.isTokenValid(refreshToken, userService.loadUserByUsername(username))) {
                UserDetails userDetails = userService.loadUserByUsername(username);
                User user = userService.findByUsername(username);

                String newAccessToken = jwtUtil.generateToken(userDetails, user.getId());

                Map<String, Object> response = new HashMap<>();
                response.put("accessToken", newAccessToken);
                response.put("tokenType", "Bearer");
                response.put("expiresIn", jwtUtil.getExpirationTime());

                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid refresh token", "message", "Please login again"));
            }
        } catch (Exception e) {
            log.error("Error during token refresh", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Token refresh failed", "message", e.getMessage()));
        }
    }

    @Operation(summary = "Get current user profile", description = "Returns profile of the authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/api/auth/profile")
    public ResponseEntity<?> getUserProfile(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "No token provided", "message", "Authorization header is required"));
            }

            String token = authHeader.substring(7);
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

                return ResponseEntity.ok(profile);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token", "message", "Please login again"));
            }
        } catch (Exception e) {
            log.error("Error fetching user profile", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Profile fetch failed", "message", e.getMessage()));
        }
    }

    @Operation(summary = "Forgot password", description = "Sends a password reset link to the provided email")
    @PostMapping("/api/auth/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");

            if (email == null || email.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Email is required", "message", "Please provide a valid email address"));
            }

            // Check if user exists
            if (!userService.existsByEmail(email)) {
                // For security reasons, don't reveal if email exists or not
                return ResponseEntity.ok()
                    .body(Map.of("message", "If the email exists, a password reset link has been sent"));
            }

            // In a real application, you would:
            // 1. Generate a secure reset token
            // 2. Store it in database with expiration time
            // 3. Send email with reset link

            // For demo purposes, we'll just simulate the process
            String resetToken = generatePasswordResetToken(email);

            log.info("Password reset requested for email: {}", email);

            // emailService.sendPasswordResetEmail(email, resetToken);  // TODO: wire up email service

            return ResponseEntity.ok(Map.of(
                "message", "If the email exists, a password reset link has been sent"
            ));

        } catch (Exception e) {
            log.error("Error during forgot password request", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Forgot password failed", "message", "An error occurred while processing your request"));
        }
    }

    @Operation(summary = "Reset password", description = "Resets user password using a valid reset token")
    @PostMapping("/api/auth/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");
            String newPassword = request.get("newPassword");
            String confirmPassword = request.get("confirmPassword");

            if (token == null || token.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Reset token is required", "message", "Invalid or missing reset token"));
            }

            if (newPassword == null || confirmPassword == null || newPassword.isBlank()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid password", "message", "New password and confirm password are required"));
            }

            if (!newPassword.equals(confirmPassword)) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Password mismatch", "message", "Passwords do not match"));
            }

            // Validate reset token and extract email
            String email = validatePasswordResetToken(token);
            if (email == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid token", "message", "Reset token is invalid or expired"));
            }

            userService.resetPassword(email, newPassword);
            log.info("Password reset successful for email: {}", email);
            return ResponseEntity.ok(Map.of("message", "Password has been reset successfully. You can now login with your new password."));

        } catch (PasswordValidator.PasswordValidationException e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Weak password", "message", e.getMessage()));

        } catch (Exception e) {
            log.error("Error during password reset", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Password reset failed", "message", "An error occurred while resetting your password"));
        }
    }

    @Operation(summary = "Verify email", description = "Confirms email address using a verification token")
    @PostMapping("/api/auth/verify-email")
    public ResponseEntity<?> verifyEmail(@Valid @RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");
            String email = request.get("email");

            if (token == null || token.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Verification token is required", "message", "Invalid or missing verification token"));
            }

            // Validate verification token
            if (!validateEmailVerificationToken(token, email)) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid token", "message", "Verification token is invalid or expired"));
            }

            // Find user and verify email
            User user = userService.findByEmail(email);
            if (user.getEmailVerified()) {
                return ResponseEntity.ok()
                    .body(Map.of("message", "Email is already verified"));
            }

            // Mark email as verified
            user.setEmailVerified(true);
            userService.updateUser(user.getId(), new RegisterRequest(
                user.getUsername(), user.getEmail(), null, user.getFirstName(), user.getLastName()
            ));

            log.info("Email verification successful for: {}", email);

            return ResponseEntity.ok()
                .body(Map.of("message", "Email has been verified successfully. You can now access all features."));

        } catch (Exception e) {
            log.error("Error during email verification", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Email verification failed", "message", "An error occurred while verifying your email"));
        }
    }

    @Operation(summary = "Resend verification email", description = "Sends a new email verification link")
    @PostMapping("/api/auth/resend-verification")
    public ResponseEntity<?> resendVerificationEmail(@Valid @RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");

            if (email == null || email.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Email is required", "message", "Please provide a valid email address"));
            }

            if (!userService.existsByEmail(email)) {
                // For security reasons, don't reveal if email exists or not
                return ResponseEntity.ok()
                    .body(Map.of("message", "If the email exists, a new verification link has been sent"));
            }

            User user = userService.findByEmail(email);
            if (user.getEmailVerified()) {
                return ResponseEntity.ok()
                    .body(Map.of("message", "Email is already verified"));
            }

            // Generate new verification token
            String verificationToken = generateEmailVerificationToken(email);

            log.info("Email verification resent for: {}", email);

            // emailService.sendVerificationEmail(email, verificationToken);  // TODO: wire up email service

            return ResponseEntity.ok(Map.of(
                "message", "If the email exists, a new verification link has been sent"
            ));

        } catch (Exception e) {
            log.error("Error during resend verification", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Resend verification failed", "message", "An error occurred while sending verification email"));
        }
    }

    @Operation(summary = "Change password", description = "Changes password for the authenticated user")
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping("/api/auth/change-password")
    public ResponseEntity<?> changePassword(HttpServletRequest request, @Valid @RequestBody Map<String, String> requestBody) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "No token provided", "message", "Authorization header is required"));
            }

            String token = authHeader.substring(7);
            String username = jwtUtil.extractUsername(token);

            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token", "message", "Please login again"));
            }

            String currentPassword = requestBody.get("currentPassword");
            String newPassword = requestBody.get("newPassword");
            String confirmPassword = requestBody.get("confirmPassword");

            if (currentPassword == null || newPassword == null || confirmPassword == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Missing required fields", "message", "Current password, new password, and confirm password are required"));
            }

            if (!newPassword.equals(confirmPassword)) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Password mismatch", "message", "New passwords do not match"));
            }

            boolean success = userService.changePassword(username, currentPassword, newPassword);
            if (!success) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid current password", "message", "The current password you entered is incorrect"));
            }

            log.info("Password changed successfully for user: {}", username);
            return ResponseEntity.ok(Map.of("message", "Password has been changed successfully"));

        } catch (PasswordValidator.PasswordValidationException e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Weak password", "message", e.getMessage()));

        } catch (Exception e) {
            log.error("Error during password change", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Password change failed", "message", "An error occurred while changing your password"));
        }
    }


    @Operation(summary = "Social login", description = "Login or register via Google, GitHub, or Facebook")
    @PostMapping("/api/auth/social/login")
    public ResponseEntity<?> socialLogin(@Valid @RequestBody SocialLoginRequest socialRequest) {
        try {
            log.info("Social login attempt with provider: {}", socialRequest.getProvider());

            // Validate the social token (optional - if you want server-side validation)
            SocialUserInfo socialUserInfo = validateSocialToken(socialRequest);

            if (socialUserInfo == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid social token", "message", "Failed to validate social authentication"));
            }

            // Check if user exists by email
            User existingUser = null;
            boolean isNewUser = false;

            try {
                existingUser = userService.findByEmail(socialUserInfo.getEmail());
            } catch (Exception e) {
                // User doesn't exist, we'll create a new one
                isNewUser = true;
            }

            if (existingUser == null && socialUserInfo.getEmail() != null) {
                // Create new user from social info
                existingUser = createUserFromSocialInfo(socialUserInfo);
                isNewUser = true;
                log.info("Created new user from social login: {}", existingUser.getEmail());
            }

            if (existingUser == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Registration failed", "message", "Unable to create user from social information"));
            }

            // Generate JWT tokens
            UserDetails userDetails = userService.loadUserByUsername(existingUser.getUsername());
            String accessToken = jwtUtil.generateToken(userDetails, existingUser.getId());
            String refreshToken = jwtUtil.generateRefreshToken(userDetails, existingUser.getId());

            // Create response
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
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Social login failed for provider: {}", socialRequest.getProvider(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Social login failed", "message", e.getMessage()));
        }
    }

    @Operation(summary = "List social providers", description = "Returns the list of supported OAuth2 providers")
    @GetMapping("/api/auth/social/providers")
    public ResponseEntity<?> getSupportedProviders() {
        Map<String, Object> providers = new HashMap<>();
        providers.put("google", Map.of("name", "Google", "enabled", true));
        providers.put("github", Map.of("name", "GitHub", "enabled", true));
        providers.put("facebook", Map.of("name", "Facebook", "enabled", true));

        return ResponseEntity.ok(Map.of("providers", providers));
    }

    // Helper method to validate social token (optional)
    private SocialUserInfo validateSocialToken(SocialLoginRequest request) {
        try {
            // For demo purposes, we'll trust the frontend validation
            // In production, you might want to validate the token with the provider

            return SocialUserInfo.builder()
                .providerId(request.getProviderId())
                .provider(request.getProvider())
                .email(request.getEmail())
                .name(request.getName())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .avatarUrl(request.getAvatarUrl())
                .username(generateUsernameFromEmail(request.getEmail()))
                .emailVerified(true) // Social logins are typically pre-verified
                .build();

        } catch (Exception e) {
            log.error("Failed to validate social token", e);
            return null;
        }
    }

    // Helper method to create user from social info
    private User createUserFromSocialInfo(SocialUserInfo socialInfo) {
        try {
            RegisterRequest registerRequest = new RegisterRequest();
            registerRequest.setEmail(socialInfo.getEmail());
            registerRequest.setUsername(generateUniqueUsername(socialInfo));
            registerRequest.setPassword(generateRandomPassword()); // Social users don't need password
            registerRequest.setFirstName(socialInfo.getFirstName() != null ? socialInfo.getFirstName() : "");
            registerRequest.setLastName(socialInfo.getLastName() != null ? socialInfo.getLastName() : "");

            User user = userService.createUser(registerRequest);

            // Mark as email verified since it comes from social provider
            user.setEmailVerified(true);

            // You might want to store additional social info
            // user.setSocialProvider(socialInfo.getProvider());
            // user.setSocialProviderId(socialInfo.getProviderId());
            // user.setAvatarUrl(socialInfo.getAvatarUrl());

            return user;

        } catch (Exception e) {
            log.error("Failed to create user from social info", e);
            throw new RuntimeException("Failed to create user from social information", e);
        }
    }

    // Helper method to generate unique username
    private String generateUniqueUsername(SocialUserInfo socialInfo) {
        String baseUsername = socialInfo.getUsername();

        if (baseUsername == null || baseUsername.trim().isEmpty()) {
            baseUsername = generateUsernameFromEmail(socialInfo.getEmail());
        }

        // Make sure username is unique
        String username = baseUsername;
        int counter = 1;

        while (userService.existsByUsername(username)) {
            username = baseUsername + counter;
            counter++;
        }

        return username;
    }

    // Helper method to generate username from email
    private String generateUsernameFromEmail(String email) {
        if (email == null) return "user" + System.currentTimeMillis();

        String username = email.split("@")[0];
        // Remove any non-alphanumeric characters
        username = username.replaceAll("[^a-zA-Z0-9]", "");

        if (username.length() < 3) {
            username = "user" + username;
        }

        return username.toLowerCase();
    }

    // Helper method to generate random password for social users
    private String generateRandomPassword() {
        // Generate a secure random password since social users don't use passwords
        return java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    // Helper methods for token generation and validation
    // In a real application, these would be more sophisticated with proper crypto and database storage

    private String generatePasswordResetToken(String email) {
        // In production, use a secure random token generator and store in database with expiration
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
            return claims.getSubject(); // email
        } catch (Exception e) {
            log.warn("Invalid password reset token: {}", e.getMessage());
            return null;
        }
    }

    private String generateEmailVerificationToken(String email) {
        // In production, use a secure random token generator and store in database with expiration
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
