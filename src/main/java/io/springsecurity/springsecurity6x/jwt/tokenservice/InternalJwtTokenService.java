package io.springsecurity.springsecurity6x.jwt.tokenservice;

import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.converter.AuthenticationConverter;
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
    public String createAccessToken(Consumer<AccessTokenBuilder> consumer) {
        DefaultAccessTokenBuilder builder = new DefaultAccessTokenBuilder();
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
    public String createRefreshToken(Consumer<RefreshTokenBuilder> consumer) {
        DefaultRefreshTokenBuilder builder = new DefaultRefreshTokenBuilder();
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
                .validity(3600000));
    }

    public void invalidateToken(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
    }

    private static class DefaultAccessTokenBuilder implements AccessTokenBuilder {
        private String username;
        private List<String> roles = new ArrayList<>();
        private Map<String, Object> claims = new HashMap<>();
        private long validity;

        public AccessTokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        public AccessTokenBuilder roles(List<String> roles) {
            this.roles = roles;
            return this;
        }

        public AccessTokenBuilder claims(Map<String, Object> claims) {
            this.claims.putAll(claims);
            return this;
        }

        public AccessTokenBuilder validity(long millis) {
            this.validity = millis;
            return this;
        }
    }

    private static class DefaultRefreshTokenBuilder implements RefreshTokenBuilder {
        private String username;
        private long validity;

        public RefreshTokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        public RefreshTokenBuilder validity(long millis) {
            this.validity = millis;
            return this;
        }
    }
}

