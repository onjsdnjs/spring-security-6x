package io.springsecurity.springsecurity6x.security.token.creator;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class InternalJwtCreator implements TokenCreator {

    private final SecretKey secretKey;

    public InternalJwtCreator(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public TokenBuilder builder() {
        return new JwtTokenBuilder(secretKey);
    }

    private static class JwtTokenBuilder implements TokenBuilder {

        private String tokenType = "access"; // 기본값
        private String username;
        private long validityMillis = 3600_000;
        private List<String> roles = Collections.emptyList();
        private Map<String, Object> customClaims = Collections.emptyMap();
        private final SecretKey key;

        JwtTokenBuilder(SecretKey key) {
            this.key = key;
        }

        @Override
        public TokenBuilder tokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        @Override
        public TokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        @Override
        public TokenBuilder validity(long validityMillis) {
            this.validityMillis = validityMillis;
            return this;
        }

        @Override
        public TokenBuilder roles(List<String> roles) {
            this.roles = roles;
            return this;
        }

        @Override
        public TokenBuilder claims(Map<String, Object> claims) {
            this.customClaims = claims;
            return this;
        }

        @Override
        public String build() {
            Instant now = Instant.now();
            Instant expiry = now.plusMillis(validityMillis);

            var builder = Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(Date.from(now))
                    .setExpiration(Date.from(expiry))
                    .claim("token_type", tokenType)
                    .claim("roles", roles)
                    .signWith(key, SignatureAlgorithm.HS256);

            if (customClaims != null && !customClaims.isEmpty()) {
                customClaims.forEach(builder::claim);
            }

            return builder.compact();
        }
    }
}


