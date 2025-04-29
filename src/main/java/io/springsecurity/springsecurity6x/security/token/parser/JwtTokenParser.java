package io.springsecurity.springsecurity6x.security.token.parser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.security.Key;
import java.util.List;
import java.util.stream.Collectors;

public class JwtTokenParser implements TokenParser {

    private final Key secretKey;

    public JwtTokenParser(Key secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public ParsedJwt parse(String token) {
        Claims claims = getClaims(token);
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
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


}

