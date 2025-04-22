package io.springsecurity.springsecurity6x.security.tokenservice;

import io.jsonwebtoken.Jwts;
import io.springsecurity.springsecurity6x.security.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.converter.AuthenticationConverter;
import org.springframework.security.core.Authentication;

import java.security.Key;
import java.util.*;
import java.util.function.Consumer;

public class ExternalJwtTokenService implements TokenService {

    private final Key secretKey;
    private final RefreshTokenStore refreshTokenStore;
    private final AuthenticationConverter authenticationConverter;

    public ExternalJwtTokenService(RefreshTokenStore refreshTokenStore, AuthenticationConverter authenticationConverter, Key secretKey) {
        this.refreshTokenStore = refreshTokenStore;
        this.authenticationConverter = authenticationConverter;
        this.secretKey = secretKey;
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

        String refreshToken = UUID.randomUUID().toString();
        refreshTokenStore.store(refreshToken, builder.username);
        return refreshToken;
    }

    @Override
    public boolean validateAccessToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Authentication getAuthenticationFromAccessToken(String token) {
        return authenticationConverter.getAuthentication(token);
    }

    @Override
    public String refreshAccessToken(String refreshToken) {
        String username = refreshTokenStore.getUsername(refreshToken);
        if (username == null) throw new RuntimeException("Invalid refresh token");

        return createAccessToken(builder -> builder
                .username(username)
                .roles(List.of("ROLE_USER"))
                .validity(3600000));
    }

    @Override
    public void invalidateToken(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
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

