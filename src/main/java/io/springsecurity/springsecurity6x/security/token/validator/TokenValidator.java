package io.springsecurity.springsecurity6x.security.token.validator;

import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import org.springframework.security.core.Authentication;

public interface TokenValidator {

    boolean validateAccessToken(String token);

    boolean validateRefreshToken(String token);

    void invalidateRefreshToken(String refreshToken);

    Authentication getAuthentication(String token);

    default boolean shouldRotateRefreshToken(String refreshToken){return false;};

    default TokenParser tokenParser(){return null;}
}
