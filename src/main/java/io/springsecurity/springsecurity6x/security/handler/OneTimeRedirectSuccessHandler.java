package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class OneTimeRedirectSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    private final String targetUrl;
    private final AuthResponseWriter responseWriter; // AuthResponseWriter 주입

    // 기존 생성자는 Assert 때문에 남겨두거나, responseWriter를 받는 생성자만 사용하도록 통일
    public OneTimeRedirectSuccessHandler(String targetUrl) {
        Assert.hasText(targetUrl, "targetUrl cannot be empty");
        this.targetUrl = targetUrl;
        this.responseWriter = null; // 이 경우 responseWriter가 없으므로 문제가 될 수 있음
        log.warn("OneTimeRedirectSuccessHandler created via single-arg constructor. AuthResponseWriter is not set!");
    }


    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to send JSON redirect for target: {}", targetUrl);
            return;
        }
        if (this.responseWriter == null) {
            log.error("AuthResponseWriter is null in OneTimeRedirectSuccessHandler. Cannot send JSON redirect. Target: {}", targetUrl);
            // 비상 리다이렉션 또는 오류 처리
            response.sendRedirect(targetUrl); // 최후의 수단
            return;
        }

        log.debug("Sending JSON redirect to {} after OTT step (User: {})", targetUrl, token != null ? token.getUsername() : "N/A");
        responseWriter.writeSuccessResponse(response, Map.of("status", "REDIRECT_REQUIRED_OTT", "redirectUrl", targetUrl), HttpServletResponse.SC_OK);
    }
}