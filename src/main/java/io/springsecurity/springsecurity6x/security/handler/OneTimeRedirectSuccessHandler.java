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
    private final AuthResponseWriter responseWriter; // 추가

    public OneTimeRedirectSuccessHandler(String targetUrl) { // 기존 생성자는 유지하되, responseWriter는 Bean 주입으로
        Assert.hasText(targetUrl, "targetUrl cannot be empty");
        this.targetUrl = targetUrl;
        this.responseWriter = null; // 이 생성자 사용 시 responseWriter는 null이 되므로 주의 또는 오류 발생시켜야 함
        // 또는 기본 JsonAuthResponseWriter(new ObjectMapper()) 사용
        log.warn("OneTimeRedirectSuccessHandler created without AuthResponseWriter. JSON response will not be possible via this instance unless responseWriter is set.");
    }


    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to send JSON redirect for {}", targetUrl);
            return;
        }

        if (this.responseWriter == null) { // responseWriter가 주입되지 않은 경우 (기존 생성자 호출 시)
            log.error("AuthResponseWriter is not set in OneTimeRedirectSuccessHandler. Cannot send JSON redirect. Falling back to direct redirect (deprecated).");
            org.springframework.security.web.RedirectStrategy redirectStrategy = new org.springframework.security.web.DefaultRedirectStrategy();
            redirectStrategy.sendRedirect(request, response, targetUrl);
            return;
        }

        log.debug("Sending JSON redirect to {} after OTT step (User: {})", targetUrl, token != null ? token.getUsername() : "N/A");
        responseWriter.writeSuccessResponse(
                response,
                Map.of("status", "SUCCESS_REDIRECT_OTT", "redirectUrl", targetUrl),
                HttpServletResponse.SC_OK);
    }
}