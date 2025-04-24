package io.springsecurity.springsecurity6x.security.token.parser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;
import java.time.Instant;

public class JwtsParser implements JwtParser {

    private final SecretKey signingKey;

    public JwtsParser(SecretKey signingKey) {
        this.signingKey = signingKey;
    }

    @Override
    public ParsedJwt parse(String token) {

        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token);
        Claims claims = jws.getBody();

        return new ParsedJwt() {
            @Override public String getId() {
                return claims.getId();
            }
            @Override public String getSubject() {
                return claims.getSubject();
            }
            @Override public Instant getExpiration() {
                return claims.getExpiration().toInstant();
            }
            @Override public <T> T getClaim(String name, Class<T> type) {
                return claims.get(name, type);
            }
        };
    }
}

