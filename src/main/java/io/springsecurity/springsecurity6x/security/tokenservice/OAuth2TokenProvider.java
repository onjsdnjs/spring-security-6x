package io.springsecurity.springsecurity6x.security.tokenservice;

import io.springsecurity.springsecurity6x.security.converter.AuthenticationConverter;
import io.springsecurity.springsecurity6x.security.tokenstore.RefreshTokenStore;
import org.springframework.security.oauth2.jwt.*;

import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

public class OAuth2TokenProvider extends JwtTokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    public OAuth2TokenProvider(JwtEncoder encoder, JwtDecoder decoder, RefreshTokenStore store, AuthenticationConverter converter) {
        super(store, converter);
        this.jwtEncoder = encoder;
        this.jwtDecoder = decoder;
    }

    @Override
    public String createAccessToken(Consumer<TokenBuilder> consumer) {
        DefaultTokenBuilder builder = new DefaultTokenBuilder();
        consumer.accept(builder);

        Instant now = Instant.now();
        Map<String, Object> claims = new HashMap<>(builder.getClaims());
        claims.putIfAbsent("roles", builder.getRoles());

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .subject(builder.getUsername())
                .issuedAt(now)
                .expiresAt(now.plusMillis(builder.getValidity()))
                .claims(c -> c.putAll(claims))
                .build();

        JwsHeader jwsHeader = JwsHeader.with(() -> "RS256").build();
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsSet)).getTokenValue();
    }

    @Override
    public String createRefreshToken(Consumer<TokenBuilder> consumer) {
        DefaultTokenBuilder builder = new DefaultTokenBuilder();
        consumer.accept(builder);

        String refreshToken = UUID.randomUUID().toString();
        refreshTokenStore().store(refreshToken, builder.getUsername());
        return refreshToken;
    }

    public boolean validateToken(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    @Override
    public boolean shouldRotateRefreshToken(String refreshToken) {
        return false;
    }

    @Override
    public String createAccessTokenFromRefresh(String refreshToken) {
        return "";
    }
}

