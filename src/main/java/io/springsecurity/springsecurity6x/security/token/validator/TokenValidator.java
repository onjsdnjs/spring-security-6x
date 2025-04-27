package io.springsecurity.springsecurity6x.security.token.validator;

import org.springframework.security.core.Authentication;

public interface TokenValidator {

    boolean validateAccessToken(String token);

    boolean validateRefreshToken(String token);

    void invalidateRefreshToken(String refreshToken);

    boolean shouldRotateRefreshToken(String refreshToken);

    Authentication getAuthentication(String token);
}
