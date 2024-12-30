package com.todo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {
    // Using a hardcoded secret for testing - replace with configuration in production
    private static final String SECRET_STRING = "ThisIsATestSecretKeyThatIsLongEnoughToBeSecure123!@#";
    private final SecretKey secretKey;

    public JwtUtil() {
        this.secretKey = Keys.hmacShaKeyFor(SECRET_STRING.getBytes());
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(secretKey)
                .compact();
    }

    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    public boolean validateToken(String token, String username) {
        try {
            return username.equals(extractUsername(token)) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Test method to verify token generation and validation
    public void testTokenValidation() {
        try {
            // 1. Generate a token
            String username = "testUser";
            String token = generateToken(username);
            System.out.println("Generated Token: " + token);

            // 2. Validate the token
            boolean isValid = validateToken(token, username);
            System.out.println("Is Token Valid? " + isValid);

            // 3. Extract and print claims
            Claims claims = getClaims(token);
            System.out.println("Subject: " + claims.getSubject());
            System.out.println("IssuedAt: " + claims.getIssuedAt());
            System.out.println("Expiration: " + claims.getExpiration());
        } catch (Exception e) {
            System.err.println("Error during validation: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        JwtUtil jwtUtil = new JwtUtil();
        jwtUtil.testTokenValidation();
    }
}