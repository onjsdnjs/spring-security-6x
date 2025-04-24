package io.springsecurity.springsecurity6x.security.tokenservice;

import io.springsecurity.springsecurity6x.security.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.converter.AuthenticationConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.*;

import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

public class InternalJwtTokenService implements TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final RefreshTokenStore refreshTokenStore;
    private final AuthenticationConverter authenticationConverter;

    public InternalJwtTokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder,
                                   RefreshTokenStore refreshTokenStore,
                                   AuthenticationConverter authenticationConverter) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.refreshTokenStore = refreshTokenStore;
        this.authenticationConverter = authenticationConverter;
    }

    @Override
    public String createAccessToken(Consumer<TokenBuilder> consumer) {
        DefaultTokenBuilder builder = new DefaultTokenBuilder();
        consumer.accept(builder);

        Instant now = Instant.now();
        Map<String, Object> claims = new HashMap<>(builder.claims);
        claims.putIfAbsent("roles", builder.roles);

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .subject(builder.username)
                .issuedAt(now)
                .expiresAt(now.plusMillis(builder.validity))
                .claims(c -> c.putAll(claims))
                .build();

        JwsHeader jwsHeader = JwsHeader.with(() -> "RS256").build();
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsSet)).getTokenValue();
    }

    @Override
    public String createRefreshToken(Consumer<TokenBuilder> consumer) {
        RefreshTokenBuilder builder = new RefreshTokenBuilder();
        consumer.accept(builder);

        String refreshToken = UUID.randomUUID().toString();
        refreshTokenStore.store(refreshToken, builder.username);
        return refreshToken;
    }

    public boolean validateAccessToken(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public Authentication getAuthenticationFromAccessToken(String token) {
        return authenticationConverter.getAuthentication(token);
    }

    public String refreshAccessToken(String refreshToken) {
        String username = refreshTokenStore.getUsername(refreshToken);
        if (username == null) throw new RuntimeException("Invalid refresh token");

        return createAccessToken(builder -> builder
                .username(username)
                .roles(List.of("ROLE_USER"))
                .validity(3600000L));
    }

    public void invalidateToken(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
    }

    private static class DefaultTokenBuilder implements TokenBuilder {
        private String username;
        private List<String> roles = new ArrayList<>();
        private Map<String, Object> claims = new HashMap<>();
        private long validity;

        public TokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        public TokenBuilder roles(List<String> roles) {
            this.roles = roles;
            return this;
        }

        public TokenBuilder claims(Map<String, Object> claims) {
            this.claims.putAll(claims);
            return this;
        }

        public TokenBuilder validity(long millis) {
            this.validity = millis;
            return this;
        }
    }

    private static class RefreshTokenBuilder implements TokenBuilder {
        private String username;
        private long validity;

        @Override
        public RefreshTokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        @Override
        public RefreshTokenBuilder validity(long validity) {
            this.validity = validity;
            return this;
        }
    }
}

