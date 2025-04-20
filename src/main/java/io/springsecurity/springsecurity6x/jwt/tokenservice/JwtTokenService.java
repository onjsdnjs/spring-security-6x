package io.springsecurity.springsecurity6x.jwt.tokenservice;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class JwtTokenService implements TokenService {

    private Key secretKey;

    @PostConstruct
    public void init() {
        secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    @Override
    public String createAccessToken(Consumer<AccessTokenBuilder> consumer) {
        DefaultAccessTokenBuilder builder = new DefaultAccessTokenBuilder();
        consumer.accept(builder);
        return Jwts.builder()
                .setSubject(builder.username)
                .addClaims(builder.claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + builder.validity))
                .signWith(secretKey)
                .compact();
    }

    @Override
    public String createRefreshToken(Consumer<RefreshTokenBuilder> consumer) {
        DefaultRefreshTokenBuilder builder = new DefaultRefreshTokenBuilder();
        consumer.accept(builder);
        return Jwts.builder()
                .setSubject(builder.username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + builder.validity))
                .signWith(secretKey)
                .compact();
    }

    private static class DefaultAccessTokenBuilder implements AccessTokenBuilder {
        private String username;
        private List<String> roles;
        private Map<String, Object> claims = new HashMap<>();
        private long validity;

        @Override
        public AccessTokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        @Override
        public AccessTokenBuilder roles(List<String> roles) {
            this.roles = roles;
            this.claims.put("roles", roles);
            return this;
        }

        @Override
        public AccessTokenBuilder claims(Map<String, Object> claims) {
            this.claims.putAll(claims);
            return this;
        }

        @Override
        public AccessTokenBuilder validity(long millis) {
            this.validity = millis;
            return this;
        }
    }

    private static class DefaultRefreshTokenBuilder implements RefreshTokenBuilder {
        private String username;
        private long validity;

        @Override
        public RefreshTokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        @Override
        public RefreshTokenBuilder validity(long millis) {
            this.validity = millis;
            return this;
        }
    }

}

