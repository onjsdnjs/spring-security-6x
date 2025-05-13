package io.springsecurity.springsecurity6x.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * MFA 중간 단계 인증 성공 시, 다음 단계 URL로 302 Redirect를 수행합니다.
 */
public class SimpleRedirectSuccessHandler implements AuthenticationSuccessHandler {
    private final String targetUrl;

    public SimpleRedirectSuccessHandler(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        response.sendRedirect(targetUrl);
    }
}