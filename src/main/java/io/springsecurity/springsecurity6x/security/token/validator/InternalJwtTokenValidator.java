package io.springsecurity.springsecurity6x.security.token.validator;

import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;

public class InternalJwtTokenValidator implements TokenValidator {

    private final JwtParser jwtParser;
    private final RefreshTokenStore refreshTokenStore;
    private final long rotationThresholdMillis;

    public InternalJwtTokenValidator(JwtParser jwtParser, RefreshTokenStore refreshTokenStore, long rotateThresholdMillis) {
        this.jwtParser = jwtParser;
        this.refreshTokenStore = refreshTokenStore;
        this.rotationThresholdMillis = rotateThresholdMillis;
    }

    @Override
    public boolean validateAccessToken(String token) {
        return jwtParser.isValidAccessToken(token);
    }

    @Override
    public boolean validateRefreshToken(String token) {
        if (!jwtParser.isValidRefreshToken(token)) {
            return false;
        }
        return refreshTokenStore.getUsername(token) != null;
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
    }

    @Override
    public boolean shouldRotateRefreshToken(String refreshToken) {
        var parsed = jwtParser.parse(refreshToken);
        long remain = parsed.expiration().toEpochMilli() - System.currentTimeMillis();
        return remain <= rotationThresholdMillis;
    }
}
