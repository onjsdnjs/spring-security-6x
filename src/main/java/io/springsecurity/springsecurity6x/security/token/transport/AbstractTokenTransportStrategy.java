package io.springsecurity.springsecurity6x.security.token.transport;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;

import java.io.IOException;
import java.util.Map;

public abstract class AbstractTokenTransportStrategy {

    protected static final String SAME_SITE = "Strict";
    protected static final boolean HTTP_ONLY = true;
    protected static final boolean SECURE = false; // 운영환경에서는 true

    protected String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    protected void addCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds, String path) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .path(path)
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .sameSite(SAME_SITE)
                .maxAge(maxAgeSeconds)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    protected void removeCookie(HttpServletResponse response, String name, String path) {
        ResponseCookie expired = ResponseCookie.from(name, "")
                .path(path)
                .httpOnly(HTTP_ONLY)
                .secure(SECURE)
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        response.addHeader("Set-Cookie", expired.toString());
    }

    protected void writeJson(HttpServletResponse response, Object body) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        try {
            new ObjectMapper().writeValue(response.getWriter(), body);
        } catch (IOException e) {
            throw new RuntimeException("JSON 응답 실패", e);
        }
    }
}

