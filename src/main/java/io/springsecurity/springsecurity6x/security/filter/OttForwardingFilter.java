package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.service.ott.CodeStore;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
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
import java.nio.charset.StandardCharsets;

@Slf4j
public class OttForwardingFilter extends OncePerRequestFilter {

    private final RequestMatcher requestMatcher; // 이 필터가 처리할 GET 요청 경로 매처
    private final CodeStore codeStore;
    private final String ottProcessingUrl; // 실제 OTT 코드 검증을 처리하는 POST URL (예: "/login/ott" 또는 "/login/mfa-ott")
    private final String failureUrl;       // 코드 관련 문제 발생 시 리다이렉트 할 UI URL (예: "/loginOtt?error=invalid_code")
    private final String usernameParameterName; // POST 요청 시 사용할 사용자 이름 파라미터명
    private final String tokenParameterName;    // POST 요청 시 사용할 토큰 값 파라미터명
    private final ContextPersistence contextPersistence;

    /**
     * OttForwardingFilter 생성자.
     * @param codeStore CodeStore 인스턴스 (null이 아니어야 함)
     * @param ottProcessingUrl 실제 OTT 코드 검증을 처리하는 URL (POST 방식, null이거나 비어있을 수 없음)
     * @param failureUrl 코드 관련 문제 발생 시 리다이렉트할 URL (null이거나 비어있을 수 없음)
     * @param filterProcessesGetUrl 이 필터가 GET 요청을 가로챌 URL (예: "/login/ott", null이거나 비어있을 수 없음)
     * @param usernameParameterName 자동 POST 제출 시 사용할 사용자 이름 파라미터 이름 (기본값: "username")
     * @param tokenParameterName 자동 POST 제출 시 사용할 토큰 값 파라미터 이름 (기본값: "token")
     */
    public OttForwardingFilter(CodeStore codeStore,
                               String ottProcessingUrl,
                               String failureUrl,
                               String filterProcessesGetUrl,
                               String usernameParameterName,
                               String tokenParameterName,
                               ContextPersistence contextPersistence) {
        Assert.notNull(codeStore, "CodeStore cannot be null");
        Assert.hasText(ottProcessingUrl, "ottProcessingUrl cannot be empty");
        Assert.hasText(failureUrl, "failureUrl cannot be empty");
        Assert.hasText(filterProcessesGetUrl, "filterProcessesGetUrl cannot be empty. This filter needs a specific GET URL to process.");

        this.codeStore = codeStore;
        this.ottProcessingUrl = ottProcessingUrl;
        this.failureUrl = failureUrl;
        this.requestMatcher = new AntPathRequestMatcher(filterProcessesGetUrl, HttpMethod.GET.name());
        this.usernameParameterName = StringUtils.hasText(usernameParameterName) ? usernameParameterName : "username";
        this.tokenParameterName = StringUtils.hasText(tokenParameterName) ? tokenParameterName : "token"; // Spring Security OneTimeTokenAuthenticationFilter 기본값
        this.contextPersistence = contextPersistence;

        log.info("OttForwardingFilter initialized. Listening for GET requests on {}. Will forward to POST {}. Failure redirect to {}. UsernameParam: '{}', TokenParam: '{}'",
                filterProcessesGetUrl, ottProcessingUrl, failureUrl, this.usernameParameterName, this.tokenParameterName);
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
            log.warn("OttForwardingFilter: 'code' parameter is missing in GET request to {}. Redirecting to failure URL: {}",
                    request.getRequestURI(), failureUrl);
            response.sendRedirect(buildRedirectUrl(request, failureUrl, "code_missing"));
            return;
        }

        OneTimeToken oneTimeToken = codeStore.consume(code);

        if (oneTimeToken == null) {
            log.warn("OttForwardingFilter: Invalid or expired code '{}' provided. Redirecting to failure URL: {}",
                    code, failureUrl);
            response.sendRedirect(buildRedirectUrl(request, failureUrl, "invalid_or_expired_code"));
            return;
        }

        String username = oneTimeToken.getUsername();
        String tokenValue = oneTimeToken.getTokenValue();

        if (!StringUtils.hasText(username) || !StringUtils.hasText(tokenValue)) {
            log.error("OttForwardingFilter: Consumed OneTimeToken for code '{}' is invalid (missing username or tokenValue). Redirecting to failure URL: {}",
                    code, failureUrl);
            response.sendRedirect(buildRedirectUrl(request, failureUrl, "corrupted_token_data"));
            return;
        }

        log.info("OttForwardingFilter: Successfully consumed code '{}' for user '{}'. Preparing auto-POST form to {}.",
                code, username, this.ottProcessingUrl);

        // CSRF 토큰 가져오기
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken == null) {
            csrfToken = (CsrfToken) request.getAttribute("_csrf"); // 일반적인 request attribute 이름
        }

        // 자동 POST 제출 HTML 생성
        response.setContentType("text/html;charset=" + StandardCharsets.UTF_8.name());
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);

        try (PrintWriter writer = response.getWriter()) {
            writer.println("<!DOCTYPE html>");
            writer.println("<html lang=\"ko\"><head><meta charset=\"UTF-8\"><title>OTT 인증 처리 중...</title>");
            // 간단한 스타일 추가 (클라이언트가 로딩 상태를 인지하도록)
            writer.println("<style>body{display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;margin:0;font-family:Arial,sans-serif;background-color:#f4f4f4;color:#333;} " +
                    ".spinner{border:5px solid #f3f3f3;border-top:5px solid #3498db;border-radius:50%;width:50px;height:50px;animation:spin 1s linear infinite;} " +
                    "@keyframes spin{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}} .message{margin-top:20px;font-size:1.1em;}</style>");
            writer.println("</head><body>");
            writer.println("<div class=\"spinner\"></div><p class=\"message\">인증 정보를 안전하게 전송 중입니다. 잠시만 기다려주세요...</p>");
            writer.println("<form id=\"ottForwardForm\" method=\"POST\" action=\"" + request.getContextPath() + HtmlUtils.htmlEscape(this.ottProcessingUrl) + "\" style=\"display:none;\">");
            writer.println("  <input type=\"hidden\" name=\"" + HtmlUtils.htmlEscape(this.usernameParameterName) + "\" value=\"" + HtmlUtils.htmlEscape(username) + "\"/>");
            writer.println("  <input type=\"hidden\" name=\"" + HtmlUtils.htmlEscape(this.tokenParameterName) + "\" value=\"" + HtmlUtils.htmlEscape(tokenValue) + "\"/>");
            if (csrfToken != null) {
                writer.println("  <input type=\"hidden\" name=\"" + HtmlUtils.htmlEscape(csrfToken.getParameterName()) + "\" value=\"" + HtmlUtils.htmlEscape(csrfToken.getToken()) + "\"/>");
                log.debug("OttForwardingFilter: CSRF token included in auto-POST form. ParameterName: {}", csrfToken.getParameterName());
            } else {
                log.warn("OttForwardingFilter: CsrfToken not found in request attributes. Auto-POST form will NOT include CSRF token. This may cause issues if CSRF protection is enabled for POST {}", this.ottProcessingUrl);
            }
            writer.println("  <noscript><p style=\"color:red;text-align:center;\">JavaScript가 비활성화되어 자동 로그인을 진행할 수 없습니다. <br/>이메일의 링크를 다시 클릭하시거나, 문제가 지속되면 관리자에게 문의해주세요.</p>" +
                    "<button type=\"submit\" style=\"padding:10px 20px;background-color:#007bff;color:white;border:none;border-radius:4px;cursor:pointer;display:block;margin:20px auto;\">수동으로 계속</button></noscript>");
            writer.println("</form>");
            writer.println("<script type=\"text/javascript\">");
            writer.println("  try { document.getElementById('ottForwardForm').submit(); } catch(e) { console.error('Auto-submit failed:', e); document.body.innerHTML = '<p style=\"color:red;text-align:center;font-size:1.2em;\">자동 제출에 실패했습니다. 페이지를 새로고침하거나 관리자에게 문의하세요.</p>'; }");
            writer.println("</script>");
            writer.println("</body></html>");
        }
    }

    private String buildRedirectUrl(HttpServletRequest request, String baseUrl, String reason) {
        String contextPath = request.getContextPath();
        String separator = baseUrl.contains("?") ? "&" : "?";
        return contextPath + baseUrl + separator + "reason=" + reason;
    }
}