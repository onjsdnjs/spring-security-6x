package io.springsecurity.springsecurity6x.security.token.transport;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface TokenTransportHandler {

    String resolveAccessToken(HttpServletRequest request);

    String resolveRefreshToken(HttpServletRequest request);

    void sendAccessToken(HttpServletResponse response, String accessToken);

    void sendRefreshToken(HttpServletResponse response, String refreshToken);

    void clearTokens(HttpServletResponse response);
}

