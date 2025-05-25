package io.springsecurity.springsecurity6x.security.token.parser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.List;

@Slf4j
public class JwtTokenParser implements TokenParser {

    private final SecretKey secretKey;

    public JwtTokenParser(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public ParsedJwt parse(String token) {
        Claims claims = getClaims(token);
        return new ParsedJwt(
                claims.getId(),
                claims.getSubject(),
                claims.getExpiration().toInstant(),
                claims.get("roles", List.class),
                claims.get("deviceId", String.class)
        );
    }

    @Override
    public boolean isValidAccessToken(String token) {
        try {
            Claims claims = getClaims(token);
            return !"refresh".equals(claims.get("token_type"));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isValidRefreshToken(String token) {
        try {
            Claims claims = getClaims(token);
            return "refresh".equals(claims.get("token_type"));
        } catch (Exception e) {
            return false;
        }
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}

