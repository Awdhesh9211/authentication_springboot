package com.awdhx.tokenauth.service;

import com.awdhx.tokenauth.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtService {

    private static final String SECRET = "THIS_IS_A_VERY_LONG_AND_SECURE_256_BIT_SECRET_KEY_123456";

    public String generateToken(User user, int minutes) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + minutes * 60 * 1000))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes()))
                .compact();
    }
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

}

