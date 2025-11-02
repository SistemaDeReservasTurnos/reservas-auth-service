package com.servicio.reservas.auth.application.services;

import com.servicio.reservas.auth.application.ports.in.ITokenService;
import com.servicio.reservas.auth.infraestructure.users.UserDTO;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Service
public class TokenService implements ITokenService {
    @Value("${application.security.jwt.secret-key}")
    private String tokenSecretKey;
    @Value("${application.security.jwt.expiration}")
    private Long tokenExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private Long refreshTokenExpiration;

    @Override
    public String generateToken(UserDTO user) {
        return buildToken(user, tokenExpiration);
    }

    @Override
    public String generateRefreshToken(UserDTO user) {
        return buildToken(user, refreshTokenExpiration);
    }

    @Override
    public String extractUsername(String token) {
        Claims jwtToken = Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return jwtToken.getSubject();
    }

    @Override
    public boolean isTokenValid(String token, UserDTO user) {
        String username = extractUsername(token);

        return username.equals(user.getEmail()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        Claims jwtToken = Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return jwtToken.getExpiration();
    }

    private String buildToken(UserDTO user, long expiration) {
        return Jwts.builder()
                .id(user.getId().toString())
                .claims(Map.of("name", user.getName()))
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(tokenSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
