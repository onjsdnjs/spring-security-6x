package io.springsecurity.springsecurity6x.security.token.transport;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface TokenTransportStrategy {

    String resolveAccessToken(HttpServletRequest request);

    String resolveRefreshToken(HttpServletRequest request);

    void writeAccessToken(HttpServletResponse response, String accessToken);

    void writeRefreshToken(HttpServletResponse response, String refreshToken);

    void clearTokens(HttpServletResponse response);
}


