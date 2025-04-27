package io.springsecurity.springsecurity6x.security.token.transport;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class HeaderTokenTransportHandler implements TokenTransportHandler {

    private static final String ACCESS_TOKEN_HEADER  = "Authorization";
    private static final String REFRESH_TOKEN_HEADER = "X-Refresh-Token";
    private static final String BEARER_PREFIX        = "Bearer ";

    @Override
    public String extractAccessToken(HttpServletRequest request) {
        String authHeader = request.getHeader(ACCESS_TOKEN_HEADER);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String extractRefreshToken(HttpServletRequest request) {
        return request.getHeader(REFRESH_TOKEN_HEADER);
    }

    @Override
    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setHeader(ACCESS_TOKEN_HEADER, BEARER_PREFIX + accessToken);
    }

    @Override
    public void sendRefreshToken(HttpServletResponse response, String refreshToken) {
        response.setHeader(REFRESH_TOKEN_HEADER, refreshToken);
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        response.setHeader(ACCESS_TOKEN_HEADER, "");
        response.setHeader(REFRESH_TOKEN_HEADER, "");
    }
}




