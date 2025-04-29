package io.springsecurity.springsecurity6x.security.token.transport;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface TokenTransportStrategy {

    String resolveAccessToken(HttpServletRequest request);

    String resolveRefreshToken(HttpServletRequest request);

    void writeAccessToken(HttpServletResponse response, String accessToken);

    void writeRefreshToken(HttpServletResponse response, String refreshToken);

    void writeAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) throws Exception;

    void clearTokens(HttpServletResponse response);

    void setTokenService(TokenService tokenService);
}


