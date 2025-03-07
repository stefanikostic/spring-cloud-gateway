package com.elevateresume.spring_cloud_gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final SecurityJwtConfigurationProperties securityJwtConfigurationProperties;

    public String extractUsername(String token) {
        Claims claims = extractClaims(token);
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = extractClaims(token);
            String username = claims.getSubject();
            Date expiration = claims.getExpiration();

            return !expiration.before(new Date(System.currentTimeMillis()));
        } catch (Exception e) {
            return false;
        }
    }

    private Claims extractClaims(String token) {
        String secretKey = securityJwtConfigurationProperties.getSecretKey();

        return Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
