package com.example.AuthenticationBackedJava.Authentication.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class JwtBlacklistService {

    private static final Logger log = LoggerFactory.getLogger(JwtBlacklistService.class);

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

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

    public boolean isTokenBlacklisted(String token) {
        try {
            String key = BLACKLIST_PREFIX + token;
            Boolean exists = redisTemplate.hasKey(key);
            return Boolean.TRUE.equals(exists);
        } catch (Exception e) {
            log.error("Error checking if token is blacklisted: {}", token, e);
            return false;
        }
    }

}
