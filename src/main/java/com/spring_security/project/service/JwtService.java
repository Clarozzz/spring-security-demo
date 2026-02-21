package com.spring_security.project.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${secret.key}")
    private String SECRET_KEY;

    @Value("${secret.expiration}")
    private long jwtExpiration;

    @Value("${refresh.token.key}")
    private String REFRESH_KEY;

    @Value("${refresh.token.expiration}")
    private long refreshExpiration;

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration, getSignInKey(SECRET_KEY));
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration, getSignInKey(REFRESH_KEY));
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration,
            Key key
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject, getSignInKey(SECRET_KEY));
    }

    public String extractEmailFromRefreshToken(String token) {
        return extractClaim(token, Claims::getSubject, getSignInKey(REFRESH_KEY));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver, Key key) {
        final Claims claims = extractAllClaims(token, key);
        return claimsResolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userEmail = extractEmail(token);
        return (userEmail.equals(userDetails.getUsername())) && isTokenExpired(token, getSignInKey(SECRET_KEY));
    }

    public boolean isRefreshTokenValid(String token, UserDetails userDetails) {
        final String userEmail = extractEmailFromRefreshToken(token);
        return (userEmail.equals(userDetails.getUsername())) && isTokenExpired(token, getSignInKey(REFRESH_KEY));
    }

    private boolean isTokenExpired(String token, Key key) {
        return !extractExpiration(token, key).before(new Date());
    }

    private Date extractExpiration(String token, Key key) {
        return extractClaim(token, Claims::getExpiration, key);
    }

    private Claims extractAllClaims(String token, Key key) {
        return Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey(String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}