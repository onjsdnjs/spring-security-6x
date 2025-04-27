package io.springsecurity.springsecurity6x.security.token.parser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.util.List;

public class InternalJwtParser implements JwtParser {

    private final Key secretKey;

    public InternalJwtParser(Key secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public ParsedJwt parse(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return new ParsedJwt(
                claims.getId(),
                claims.getSubject(),
                claims.getExpiration().toInstant(),
                claims.get("roles", List.class)
        );
    }

    @Override
    public boolean isValidAccessToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return !"refresh".equals(claims.get("token_type"));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isValidRefreshToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return "refresh".equals(claims.get("token_type"));
        } catch (Exception e) {
            return false;
        }
    }
}

