package io.springsecurity.springsecurity6x.security.tokenstore;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.time.Instant;

/**
 * JJWT 라이브러리를 쓰는 구현체.
 * parse() 내부에서만 io.jsonwebtoken API 를 사용.
 */
public class OAuth2RefreshTokenParser implements RefreshTokenParser {

    private final SecretKey signingKey;

    public OAuth2RefreshTokenParser(SecretKey signingKey) {
        this.signingKey = signingKey;
    }

    @Override
    public ParsedToken parse(String token) {

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // 내부 클래스로 ParsedToken 구현
        return new ParsedToken() {
            @Override public String getId() {
                return claims.getId();
            }
            @Override public Instant getExpiration() {
                return claims.getExpiration().toInstant();
            }
            @Override public Object getClaim(String name) {
                return claims.get(name);
            }
        };
    }
}
