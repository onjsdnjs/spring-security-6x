package io.springsecurity.springsecurity6x.security.token.validator;

import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class DefaultJwtTokenValidator implements TokenValidator {

    private final TokenParser tokenParser;
    private final RefreshTokenStore refreshTokenStore;
    private final long rotationThresholdMillis;

    public DefaultJwtTokenValidator(TokenParser tokenParser, RefreshTokenStore refreshTokenStore, long rotateThresholdMillis) {
        this.tokenParser = tokenParser;
        this.refreshTokenStore = refreshTokenStore;
        this.rotationThresholdMillis = rotateThresholdMillis;
    }

    @Override
    public boolean validateAccessToken(String token) {
        return tokenParser.isValidAccessToken(token);
    }

    @Override
    public boolean validateRefreshToken(String token) {
        return tokenParser.isValidRefreshToken(token)
                && refreshTokenStore.getUsername(token) != null;
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
    }

    @Override
    public boolean shouldRotateRefreshToken(String refreshToken) {
        ParsedJwt p = tokenParser.parse(refreshToken);
        return p.expiration().toEpochMilli() - System.currentTimeMillis() <= rotationThresholdMillis;
    }

    @Override
    public Authentication getAuthentication(String token) {
        ParsedJwt parsedJwt = tokenParser.parse(token);

        return new UsernamePasswordAuthenticationToken(
                parsedJwt.subject(),
                null,
                parsedJwt.roles().stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList()
        );
    }
}
