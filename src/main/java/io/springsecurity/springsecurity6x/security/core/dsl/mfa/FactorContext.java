package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

import java.util.HashMap;
import java.util.Map;

/**
 * MFA 핸들러 간 공유되는 인증 컨텍스트
 */
public class FactorContext {
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private Authentication authentication;
    private final Map<String, Object> data = new HashMap<>();

    public FactorContext(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    public void put(String key, Object value) {
        data.put(key, value);
    }

    public <T> T get(String key, Class<T> type) {
        return (T) data.get(key);
    }

    public void clear() {
        data.clear();
    }
}


