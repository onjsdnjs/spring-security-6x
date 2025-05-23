package io.springsecurity.springsecurity6x.security.token.creator;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.*;

public class JwtTokenCreator implements TokenCreator {

    private final SecretKey secretKey;

    public JwtTokenCreator(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public String createToken(TokenRequest req) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(req.getUsername())
                .claim("roles", req.getRoles())
                .claim("token_type", req.getTokenType())
                .claim("deviceId", req.getDeviceId())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(req.getValidity())))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }
}


