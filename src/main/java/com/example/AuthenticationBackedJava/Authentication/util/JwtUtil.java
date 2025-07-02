package com.example.AuthenticationBackedJava.Authentication.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    @Value("${jwt.refresh-expiration}")
    private Long refreshExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("authorities", userDetails.getAuthorities());
        return createToken(claims, userDetails.getUsername(), expiration);
    }

    public String generateRefreshToken(UserDetails userDetails, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("tokenType", "refresh");
        return createToken(claims, userDetails.getUsername(), refreshExpiration);
    }

    private String createToken(Map<String, Object> claims, String subject, Long expirationTime) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);
        String jti = UUID.randomUUID().toString(); // Generate unique JTI

        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setId(jti) // Set JTI (JWT ID)
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    public Boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        return isTokenValid(token, userDetails);
    }

    public Long getExpirationTime() {
        return expiration;
    }

    public Long getRefreshExpirationTime() {
        return refreshExpiration;
    }

    public String generateTokenWithCustomExpiration(UserDetails userDetails, Long userId, Long customExpiration) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("authorities", userDetails.getAuthorities());
        return createToken(claims, userDetails.getUsername(), customExpiration);
    }

    public Long extractUserId(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("userId", Long.class);
    }

    public String getTokenType(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("tokenType", String.class);
    }

    public Boolean isRefreshToken(String token) {
        String tokenType = getTokenType(token);
        return "refresh".equals(tokenType);
    }

    public Long getRemainingExpirationTime(String token) {
        Date expiration = extractExpiration(token);
        Date now = new Date();
        if (expiration.after(now)) {
            return expiration.getTime() - now.getTime();
        }
        return 0L;
    }

    public Long getRemainingExpirationTimeInSeconds(String token) {
        return getRemainingExpirationTime(token) / 1000;
    }
}
