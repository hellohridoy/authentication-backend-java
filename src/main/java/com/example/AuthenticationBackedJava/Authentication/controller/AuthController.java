package com.example.AuthenticationBackedJava.Authentication.controller;

import com.example.AuthenticationBackedJava.Authentication.dto.LoginRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.RegisterRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.social.SocialLoginRequest;
import com.example.AuthenticationBackedJava.Authentication.service.AuthService;
import com.example.AuthenticationBackedJava.Authentication.validation.PasswordValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Register, login, logout, token management, password reset, email verification, and social login")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    @Operation(summary = "Register a new user", description = "Creates a new account and returns JWT tokens immediately")
    @PostMapping("/api/auth/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            Map<String, Object> response = authService.register(registerRequest);
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
            return ResponseEntity.ok(authService.login(loginRequest));
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
            String token = extractTokenFromRequest(request);
            if (token == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid token format", "message", "Authorization header must start with 'Bearer '"));
            }
            return ResponseEntity.ok(authService.logout(token));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Invalid token", "message", e.getMessage()));
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
            String token = extractTokenFromRequest(request);
            if (token == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid token format", "message", "Authorization header must start with 'Bearer '"));
            }
            return ResponseEntity.ok(authService.refreshToken(token));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid refresh token", "message", "Please login again"));
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
            String token = extractTokenFromRequest(request);
            if (token == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "No token provided", "message", "Authorization header is required"));
            }
            return ResponseEntity.ok(authService.getUserProfile(token));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid token", "message", "Please login again"));
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
            return ResponseEntity.ok(authService.forgotPassword(email));
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

            return ResponseEntity.ok(authService.resetPassword(token, newPassword, confirmPassword));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Password mismatch or invalid token", "message", e.getMessage()));
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

            return ResponseEntity.ok(authService.verifyEmail(token, email));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Invalid token", "message", e.getMessage()));
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
            return ResponseEntity.ok(authService.resendVerificationEmail(email));
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
            String token = extractTokenFromRequest(request);
            if (token == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "No token provided", "message", "Authorization header is required"));
            }

            String currentPassword = requestBody.get("currentPassword");
            String newPassword = requestBody.get("newPassword");
            String confirmPassword = requestBody.get("confirmPassword");

            if (currentPassword == null || newPassword == null || confirmPassword == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Missing required fields", "message", "Current password, new password, and confirm password are required"));
            }

            return ResponseEntity.ok(authService.changePassword(token, currentPassword, newPassword, confirmPassword));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Invalid input", "message", e.getMessage()));
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
            return ResponseEntity.ok(authService.socialLogin(socialRequest));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Social login failed", "message", e.getMessage()));
        } catch (Exception e) {
            log.error("Social login failed for provider: {}", socialRequest.getProvider(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Social login failed", "message", e.getMessage()));
        }
    }

    @Operation(summary = "List social providers", description = "Returns the list of supported OAuth2 providers")
    @GetMapping("/api/auth/social/providers")
    public ResponseEntity<?> getSupportedProviders() {
        return ResponseEntity.ok(authService.getSupportedProviders());
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}
