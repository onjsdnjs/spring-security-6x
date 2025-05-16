package io.springsecurity.springsecurity6x.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

import java.io.IOException;

/**
 * OTT (One-Time Token) 생성 또는 중간 인증 성공 후, 지정된 URL로 리다이렉트하는 핸들러.
 * 주로 MFA 흐름에서 다음 단계의 UI로 사용자를 안내할 때 사용됩니다.
 */
@Slf4j
public class OneTimeRedirectSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    private final String targetUrl;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * @param targetUrl 리다이렉션할 대상 URL (null이거나 비어있을 수 없음)
     */
    public OneTimeRedirectSuccessHandler(String targetUrl) {
        Assert.hasText(targetUrl, "targetUrl cannot be empty");
        this.targetUrl = targetUrl;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        // OneTimeToken 파라미터는 OneTimeTokenGenerationSuccessHandler 인터페이스에서 요구하지만,
        // 이 핸들러의 주 목적은 생성된 토큰 자체를 사용하기보다는 지정된 URL로 리다이렉션하는 것입니다.
        // 토큰 정보가 리다이렉션 URL에 필요하다면 여기서 targetUrl을 동적으로 구성할 수 있습니다.
        // 예: String finalTargetUrl = targetUrl + "?ott_user=" + URLEncoder.encode(token.getUsername(), StandardCharsets.UTF_8);

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
            return;
        }

        log.debug("Redirecting to {} after OTT step (User: {})", targetUrl, token != null ? token.getUsername() : "N/A");
        redirectStrategy.sendRedirect(request, response, targetUrl);
    }
}