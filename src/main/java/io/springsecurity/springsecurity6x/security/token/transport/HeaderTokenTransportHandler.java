package io.springsecurity.springsecurity6x.security.token.transport;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;

public class HeaderTokenTransportHandler implements TokenTransportHandler {

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return request.getHeader("X-Refresh-Token");
    }

    @Override
    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
    }

    @Override
    public void sendRefreshToken(HttpServletResponse response, String refreshToken) {
        response.setHeader("X-Refresh-Token", refreshToken);
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        response.setHeader(HttpHeaders.AUTHORIZATION, "");
        response.setHeader("X-Refresh-Token", "");
    }
}

