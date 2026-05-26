package com.ivansario.secureauth.security;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/**
 * Utility for JWT generation and validation.
 *
 * Reads the secret key and expiration time from environment variables
 * and provides methods to generate tokens, extract the username and validate tokens.
 */
@Component
public class JwtUtil {

    @Value("${JWT_SECRET_KEY}")
    private String jwtSecret;

    @Value("${JWT_EXPIRATION}")
    private Long jwtExpiration;

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Genera un JWT para el {@link UserDetails} proporcionado.
     *
     * @param userDetails detalles del usuario (se usa username como subject)
     * @return token JWT firmado
     */
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                   .setSubject(userDetails.getUsername())
                   .setIssuedAt(new Date())
                   .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                   .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                   .compact();
    }

    /**
     * Extrae el nombre de usuario (subject) del token JWT.
     *
     * @param token JWT
     * @return nombre de usuario contenido en el token
     */
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Valida que el token corresponda al usuario y que no esté expirado.
     *
     * @param token JWT a validar
     * @param userDetails detalles del usuario esperados
     * @return {@code true} si el token es válido, {@code false} en caso contrario
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return (userDetails.getUsername().equals(username) && !isTokenExpired(token));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                   .setSigningKey(getSigningKey())
                   .build()
                   .parseClaimsJws(token)
                   .getBody();
    }

    private boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }
}
