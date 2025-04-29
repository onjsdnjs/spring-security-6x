package io.springsecurity.springsecurity6x.security.token.transport;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface TokenTransportStrategy {

    String resolveAccessToken(HttpServletRequest request);

    String resolveRefreshToken(HttpServletRequest request);

    void writeAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken);

    void clearTokens(HttpServletResponse response);

    default void setTokenService(TokenService tokenService){};
}


