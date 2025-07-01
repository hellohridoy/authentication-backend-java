package com.example.AuthenticationBackedJava.Authentication.controller;

import com.example.AuthenticationBackedJava.Authentication.components.JwtUtil;
import com.example.AuthenticationBackedJava.Authentication.dto.LoginRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.LoginResponse;
import com.example.AuthenticationBackedJava.Authentication.dto.RegisterRequest;
import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.service.JwtBlacklistService;
import com.example.AuthenticationBackedJava.Authentication.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JwtBlacklistService jwtBlacklistService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            // Check if user already exists
            if (userService.existsByEmail(registerRequest.getEmail())) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Email already registered", "message", "Please use a different email"));
            }

            if (userService.existsByUsername(registerRequest.getUsername())) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Username already taken", "message", "Please choose a different username"));
            }

            // Create new user
            User user = userService.createUser(registerRequest);

            Map<String, Object> response = new HashMap<>();
            response.put("message", "User registered successfully");
            response.put("userId", user.getId());
            response.put("username", user.getUsername());
            response.put("email", user.getEmail());

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            log.error("Error during user registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Registration failed", "message", e.getMessage()));
        }
    }

    @PostMapping("/login")
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

    @PostMapping("/logout")
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

    @PostMapping("/refresh-token")
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

    @GetMapping("/profile")
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
}
