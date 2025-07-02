package com.example.AuthenticationBackedJava.Authentication.util;

import com.example.AuthenticationBackedJava.Authentication.service.JwtBlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtBlacklistFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtBlacklistFilter.class);

    @Autowired
    private JwtBlacklistService jwtBlacklistService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String token = null;
        String jti = null;

        // Extract token from Authorization header
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);

            try {
                // Extract JTI from token
                Claims claims = jwtUtil.extractAllClaims(token);
                jti = claims.getId();

                // Check if token is blacklisted
                if (jti != null && jwtBlacklistService.isTokenBlacklisted(jti)) {
                    log.warn("Blocked request with blacklisted token: {}", jti);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Token has been invalidated\",\"message\":\"Please login again\"}");
                    return;
                }

            } catch (ExpiredJwtException e) {
                log.debug("Token is expired: {}", e.getMessage());
                // Let the expired token be handled by other filters/components
            } catch (JwtException e) {
                log.warn("Invalid JWT token: {}", e.getMessage());
                // Let invalid tokens be handled by other filters/components
            } catch (Exception e) {
                log.error("Error processing JWT token in blacklist filter", e);
                // Continue processing to avoid blocking valid requests due to unexpected errors
            }
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        // Skip filter for public endpoints
        return path.startsWith("/api/auth/login") ||
            path.startsWith("/api/auth/register") ||
            path.startsWith("/api/auth/forgot-password") ||
            path.startsWith("/api/auth/reset-password") ||
            path.startsWith("/api/public/") ||
            path.startsWith("/actuator/") ||
            path.startsWith("/swagger-ui/") ||
            path.startsWith("/v3/api-docs/");
    }
}
