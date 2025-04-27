package io.springsecurity.springsecurity6x.security.token.validator;

public interface TokenValidator {

    boolean validateAccessToken(String token);

    boolean validateRefreshToken(String token);

    void invalidateRefreshToken(String refreshToken);

    boolean shouldRotateRefreshToken(String refreshToken);
}
