package io.springsecurity.springsecurity6x.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.io.IOException;

/**
 * OTP 중간 단계용 OneTimeTokenGenerationSuccessHandler
 */
class OneTimeRedirectSuccessHandler implements OneTimeTokenGenerationSuccessHandler {
    private final String targetUrl;

    public OneTimeRedirectSuccessHandler(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token) throws IOException {
        response.sendRedirect(targetUrl);
    }
}