package io.springsecurity.springsecurity6x.security.token.transport;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static io.springsecurity.springsecurity6x.security.token.service.TokenService.*;

public class HeaderTokenStrategy implements TokenTransportStrategy {


    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        String authHeader = request.getHeader(ACCESS_TOKEN_HEADER);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return request.getHeader(REFRESH_TOKEN_HEADER);
    }

    @Override
    public void writeAccessToken(HttpServletResponse response, String accessToken) {
        response.setHeader(ACCESS_TOKEN_HEADER, BEARER_PREFIX + accessToken);
    }

    @Override
    public void writeRefreshToken(HttpServletResponse response, String refreshToken) {
        response.setHeader(REFRESH_TOKEN_HEADER, refreshToken);
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        response.setHeader(ACCESS_TOKEN_HEADER, "");
        response.setHeader(REFRESH_TOKEN_HEADER, "");
    }
}




