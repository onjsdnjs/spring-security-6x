package io.springsecurity.springsecurity6x.security.token.validator;

import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class DefaultJwtTokenValidator implements TokenValidator {

    private final JwtParser jwtParser;
    private final RefreshTokenStore refreshTokenStore;
    private final long rotationThresholdMillis;

    public DefaultJwtTokenValidator(JwtParser jwtParser, RefreshTokenStore refreshTokenStore, long rotateThresholdMillis) {
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

    @Override
    public Authentication getAuthentication(String token) {
        ParsedJwt parsedJwt = jwtParser.parse(token);

        return new UsernamePasswordAuthenticationToken(
                parsedJwt.subject(),
                null,
                parsedJwt.roles().stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList()
        );
    }
}
