package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.service.ott.CodeStore;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class OttForwardingFilter extends OncePerRequestFilter {

    // 이 필터는 "/login/ott" (GET) 요청만 처리하도록 RequestMatcher 설정
    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/login/ott", HttpMethod.GET.name());
    private final CodeStore codeStore;
    private final String ottProcessingUrl; // 실제 OTT 검증을 처리하는 POST URL (예: "/login/ott")
    private final String failureUrl;       // 코드 검증 실패 또는 code 파라미터 없을 시 리다이렉트 할 URL (예: "/loginOtt?error=invalid_code")

    /**
     * OttForwardingFilter 생성자.
     * @param codeStore CodeStore 인스턴스
     * @param ottProcessingUrl 실제 OTT 코드 검증을 처리하는 URL (POST)
     * @param failureUrl 코드 관련 문제 발생 시 리다이렉트할 URL
     */
    public OttForwardingFilter(CodeStore codeStore, String ottProcessingUrl, String failureUrl) {
        Assert.notNull(codeStore, "CodeStore cannot be null");
        Assert.hasText(ottProcessingUrl, "ottProcessingUrl cannot be empty");
        Assert.hasText(failureUrl, "failureUrl cannot be empty");
        this.codeStore = codeStore;
        this.ottProcessingUrl = ottProcessingUrl;
        this.failureUrl = failureUrl;
        log.info("OttForwardingFilter initialized. Forwarding GET /login/ott to POST {}. Failure redirect to {}.", ottProcessingUrl, failureUrl);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("OttForwardingFilter: Processing GET request for {}", request.getRequestURI());

        String code = request.getParameter("code");

        if (!StringUtils.hasText(code)) {
            log.warn("OttForwardingFilter: 'code' parameter is missing in GET request to /login/ott. Redirecting to failure URL.");
            response.sendRedirect(request.getContextPath() + failureUrl + "&reason=code_missing");
            return;
        }

        OneTimeToken oneTimeToken = codeStore.consume(code);

        if (oneTimeToken == null) {
            log.warn("OttForwardingFilter: Invalid or expired code '{}' provided. Redirecting to failure URL.", code);
            response.sendRedirect(request.getContextPath() + failureUrl + "&reason=invalid_or_expired_code");
            return;
        }

        String username = oneTimeToken.getUsername();
        String tokenValue = oneTimeToken.getTokenValue();

        if (!StringUtils.hasText(username) || !StringUtils.hasText(tokenValue)) {
            log.error("OttForwardingFilter: Consumed OneTimeToken is invalid (missing username or tokenValue). Code: '{}'. Redirecting to failure URL.", code);
            response.sendRedirect(request.getContextPath() + failureUrl + "&reason=corrupted_token_data");
            return;
        }

        log.info("OttForwardingFilter: Successfully consumed code '{}' for user '{}'. Preparing auto-POST to {}.",
                code, username, this.ottProcessingUrl);

        // CSRF 토큰 가져오기 (Spring Security가 request attribute에 저장)
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        // 또는 "_csrf" 이름으로 직접 가져올 수도 있음:
        // CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");


        // 자동 POST 제출 HTML 생성
        response.setContentType("text/html;charset=UTF-8");
        try (PrintWriter writer = response.getWriter()) {
            writer.println("<!DOCTYPE html>");
            writer.println("<html><head><title>OTT Login Processing...</title></head><body>");
            writer.println("<form id=\"ottForwardForm\" method=\"POST\" action=\"" + request.getContextPath() + HtmlUtils.htmlEscape(this.ottProcessingUrl) + "\">");
            writer.println("<input type=\"hidden\" name=\"username\" value=\"" + HtmlUtils.htmlEscape(username) + "\"/>");
            writer.println("<input type=\"hidden\" name=\"token\" value=\"" + HtmlUtils.htmlEscape(tokenValue) + "\"/>"); // Spring Security OneTimeTokenAuthenticationFilter는 'token' 파라미터 기대
            if (csrfToken != null) {
                writer.println("<input type=\"hidden\" name=\"" + HtmlUtils.htmlEscape(csrfToken.getParameterName()) + "\" value=\"" + HtmlUtils.htmlEscape(csrfToken.getToken()) + "\"/>");
            }
            writer.println("<noscript><p>JavaScript가 비활성화되어 자동 로그인을 진행할 수 없습니다. 버튼을 눌러 수동으로 진행해주세요.</p><button type=\"submit\">로그인 계속</button></noscript>");
            writer.println("</form>");
            writer.println("<p style=\"text-align:center; margin-top: 50px;\">OTT 자동 로그인 처리 중입니다. 잠시만 기다려주세요...</p>");
            writer.println("<script type=\"text/javascript\">document.getElementById('ottForwardForm').submit();</script>");
            writer.println("</body></html>");
        }
    }
}