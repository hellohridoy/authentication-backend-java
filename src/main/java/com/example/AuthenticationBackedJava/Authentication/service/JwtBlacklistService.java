package com.example.AuthenticationBackedJava.Authentication.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
public class JwtBlacklistService {

    private static final Logger log = LoggerFactory.getLogger(JwtBlacklistService.class);

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

    /**
     * Blacklist a JWT token with specific expiration time
     * @param token The JWT token ID (JTI) to blacklist
     * @param expirationTimeInSeconds How long to keep the token in blacklist
     */
    public void blacklistToken(String token, long expirationTimeInSeconds) {
        try {
            String key = BLACKLIST_PREFIX + token;
            // Store the token with expiration time
            redisTemplate.opsForValue().set(key, "blacklisted", Duration.ofSeconds(expirationTimeInSeconds));
            log.info("Token blacklisted successfully: {}", token);
        } catch (Exception e) {
            log.error("Error blacklisting token: {}", token, e);
            throw new RuntimeException("Failed to blacklist token", e);
        }
    }

    /**
     * Blacklist a JWT token with default expiration time (24 hours)
     * @param token The JWT token ID (JTI) to blacklist
     */
    public void blacklistToken(String token) {
        // Default to 24 hours if no expiration time provided
        blacklistToken(token, 24 * 60 * 60);
    }

    /**
     * Check if a JWT token is blacklisted
     * @param token The JWT token ID (JTI) to check
     * @return true if token is blacklisted, false otherwise
     */
    public boolean isTokenBlacklisted(String token) {
        try {
            String key = BLACKLIST_PREFIX + token;
            Boolean exists = redisTemplate.hasKey(key);
            return Boolean.TRUE.equals(exists);
        } catch (Exception e) {
            log.error("Error checking if token is blacklisted: {}", token, e);
            // In case of Redis error, assume token is not blacklisted to avoid blocking valid requests
            return false;
        }
    }

    /**
     * Remove a token from blacklist (not typically needed as tokens expire automatically)
     * @param token The JWT token ID (JTI) to remove from blacklist
     */
    public void removeFromBlacklist(String token) {
        try {
            String key = BLACKLIST_PREFIX + token;
            redisTemplate.delete(key);
            log.info("Token removed from blacklist: {}", token);
        } catch (Exception e) {
            log.error("Error removing token from blacklist: {}", token, e);
        }
    }

    /**
     * Clear all blacklisted tokens (use with caution)
     */
    public void clearAllBlacklistedTokens() {
        try {
            String pattern = BLACKLIST_PREFIX + "*";
            redisTemplate.delete(redisTemplate.keys(pattern));
            log.info("All blacklisted tokens cleared");
        } catch (Exception e) {
            log.error("Error clearing all blacklisted tokens", e);
        }
    }
}
