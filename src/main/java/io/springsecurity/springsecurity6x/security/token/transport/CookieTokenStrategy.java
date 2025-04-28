package io.springsecurity.springsecurity6x.security.token.transport;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;

import static io.springsecurity.springsecurity6x.security.token.service.TokenService.ACCESS_TOKEN;
import static io.springsecurity.springsecurity6x.security.token.service.TokenService.REFRESH_TOKEN;

public class CookieTokenStrategy implements TokenTransportStrategy {

    private static final String COOKIE_PATH          = "/";
    private static final boolean HTTP_ONLY           = true;
    private static final boolean SECURE              = false; // 운영에서는 true
    private static final String SAME_SITE            = "Strict";

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        return extractCookie(request, ACCESS_TOKEN);
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return extractCookie(request, REFRESH_TOKEN);
    }

    private String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    @Override
    public void writeAccessToken(HttpServletResponse response, String accessToken) {
        addCookie(response, ACCESS_TOKEN, accessToken, 3600); // 1시간
    }

    @Override
    public void writeRefreshToken(HttpServletResponse response, String refreshToken) {
        addCookie(response, REFRESH_TOKEN, refreshToken, 604800); // 7일
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        removeCookie(response, ACCESS_TOKEN);
        removeCookie(response, REFRESH_TOKEN);
    }

    private void addCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .path(COOKIE_PATH)
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .sameSite(SAME_SITE)
                .maxAge(maxAgeSeconds)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    private void removeCookie(HttpServletResponse response, String name) {
        ResponseCookie expired = ResponseCookie.from(name, "")
                .path(COOKIE_PATH)
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        response.addHeader("Set-Cookie", expired.toString());
    }
}



