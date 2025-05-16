package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Map;

@RequiredArgsConstructor
public class SimpleRedirectSuccessHandler implements AuthenticationSuccessHandler {
    private final String targetUrl;
    private final AuthResponseWriter responseWriter; // 추가

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        responseWriter.writeSuccessResponse(
                response,
                Map.of("status", "SUCCESS_REDIRECT", "redirectUrl", targetUrl),
                HttpServletResponse.SC_OK);
    }
}