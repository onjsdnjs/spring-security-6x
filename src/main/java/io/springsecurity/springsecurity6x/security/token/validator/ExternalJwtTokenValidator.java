package io.springsecurity.springsecurity6x.security.token.validator;

import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;

public class ExternalJwtTokenValidator implements TokenValidator {

    private final JwtParser jwtParser;
    private final RefreshTokenStore refreshTokenStore;
    private final long rotationThresholdMillis = 12 * 60 * 60 * 1000; // 12시간

    public ExternalJwtTokenValidator(JwtParser jwtParser, RefreshTokenStore refreshTokenStore) {
        this.jwtParser = jwtParser;
        this.refreshTokenStore = refreshTokenStore;
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
        ParsedJwt parsedJwt = jwtParser.parse(refreshToken);
        long remainingTimeMillis = parsedJwt.expiration().toEpochMilli() - System.currentTimeMillis();
        return remainingTimeMillis <= rotationThresholdMillis;
    }
}

