package io.springsecurity.springsecurity6x.security.token.transport;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CookieTokenTransportHandler implements TokenTransportHandler {

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        return getCookieValue(request, TokenService.ACCESS_TOKEN);
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return getCookieValue(request, TokenService.REFRESH_TOKEN);
    }

    @Override
    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        addTokenCookie(response, TokenService.ACCESS_TOKEN, accessToken, 3600);
    }

    @Override
    public void sendRefreshToken(HttpServletResponse response, String refreshToken) {
        addTokenCookie(response, TokenService.REFRESH_TOKEN, refreshToken, 7 * 24 * 3600);
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        addTokenCookie(response, TokenService.ACCESS_TOKEN, "", 0);
        addTokenCookie(response, TokenService.REFRESH_TOKEN, "", 0);
    }

    private String getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (name.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void addTokenCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }
}

