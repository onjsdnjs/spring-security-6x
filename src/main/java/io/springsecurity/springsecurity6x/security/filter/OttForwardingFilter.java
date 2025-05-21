package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
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
import java.util.Objects;

@Slf4j
public class OttForwardingFilter extends OncePerRequestFilter {

    private final RequestMatcher requestMatcher; // 이 필터가 처리할 GET 요청 경로 매처
    private final CodeStore codeStore;
    private final String ottProcessingUrl; // 실제 OTT 코드 검증을 처리하는 POST URL
    private final String failureUrl;       // 코드 관련 문제 발생 시 리다이렉트 할 UI URL
    private final String usernameParameterName;
    private final String tokenParameterName;
    @Nullable
    private final ContextPersistence contextPersistence; // MFA 흐름에서 FactorContext 접근용

    /**
     * OttForwardingFilter 생성자.
     * @param codeStore CodeStore 인스턴스
     * @param ottProcessingUrl 실제 OTT 코드 검증을 처리하는 URL (POST 방식, 예: "/login/ott" 또는 "/login/mfa-ott")
     * @param failureUrl 코드 관련 문제 발생 시 리다이렉트할 UI URL (예: "/loginOtt?error" 또는 "/mfa/challenge/ott?error")
     * @param filterProcessesGetUrl 이 필터가 GET 요청을 가로챌 URL (예: "/login/ott" 또는 "/login/mfa-ott")
     * @param usernameParameterName 자동 POST 제출 시 사용할 사용자 이름 파라미터 이름 (기본값: "username")
     * @param tokenParameterName 자동 POST 제출 시 사용할 토큰 값 파라미터 이름 (기본값: "token")
     * @param contextPersistence MFA 플로우에서 사용될 경우 FactorContext 로드를 위한 ContextPersistence (단일 인증 시에는 null 전달 가능)
     */
    public OttForwardingFilter(CodeStore codeStore,
                               String ottProcessingUrl,
                               String failureUrl,
                               String filterProcessesGetUrl,
                               @Nullable String usernameParameterName,
                               @Nullable String tokenParameterName,
                               @Nullable ContextPersistence contextPersistence) {
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

        log.info("OttForwardingFilter initialized. Listening for GET [{}], Forwarding POST to [{}], Failure UI [{}], UsernameParam ['{}'], TokenParam ['{}'], ContextPersistence provided: {}",
                filterProcessesGetUrl, ottProcessingUrl, failureUrl, this.usernameParameterName, this.tokenParameterName, (contextPersistence != null));
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
            response.sendRedirect(buildRedirectUrlWithReason(request, failureUrl, "code_missing"));
            return;
        }

        OneTimeToken oneTimeToken = codeStore.consume(code);

        if (oneTimeToken == null) {
            log.warn("OttForwardingFilter: Invalid or expired code '{}' provided. Redirecting to failure URL: {}",
                    code, failureUrl);
            response.sendRedirect(buildRedirectUrlWithReason(request, failureUrl, "invalid_or_expired_code"));
            return;
        }

        String usernameFromOtt = oneTimeToken.getUsername();
        String tokenValueFromOtt = oneTimeToken.getTokenValue();

        if (!StringUtils.hasText(usernameFromOtt) || !StringUtils.hasText(tokenValueFromOtt)) {
            log.error("OttForwardingFilter: Consumed OneTimeToken for code '{}' is invalid (missing username or tokenValue). Redirecting to failure URL: {}",
                    code, failureUrl);
            response.sendRedirect(buildRedirectUrlWithReason(request, failureUrl, "corrupted_ott_data"));
            return;
        }

        // MFA 플로우인 경우, FactorContext의 사용자와 OneTimeToken의 사용자가 일치하는지 추가 검증
        if (this.contextPersistence != null) {
            FactorContext factorContext = this.contextPersistence.contextLoad(request);
            if (factorContext != null) { // MFA 세션 진행 중
                if (!Objects.equals(factorContext.getUsername(), usernameFromOtt)) {
                    log.warn("OttForwardingFilter (MFA Context Active): Username mismatch! FactorContext user: '{}', OTT user: '{}'. Code: '{}'. This could indicate a session hijacking attempt or misconfiguration.",
                            factorContext.getUsername(), usernameFromOtt, code);
                    // MFA 세션이 있는데 사용자가 다르면, 심각한 문제일 수 있으므로 MFA 세션을 무효화하고 실패 처리
                    this.contextPersistence.deleteContext(request);
                    response.sendRedirect(buildRedirectUrlWithReason(request, failureUrl, "mfa_user_mismatch"));
                    return;
                }
                // MFA 플로우이고, 현재 처리 중인 Factor가 OTT인지, stepId가 일치하는지 등의 추가 검증 가능.
                // 예를 들어, factorContext.getCurrentProcessingFactor() == AuthType.OTT 와
                // factorContext.getCurrentStepId()가 이 OTT 단계의 stepId와 일치하는지 확인.
                // 이 필터의 주 목적은 포워딩이므로, 복잡한 상태 변경은 후속 핸들러가 담당.
                log.debug("OttForwardingFilter: MFA FactorContext loaded for user '{}', session '{}'. Proceeding with OTT forwarding. Current MFA State: {}",
                        factorContext.getUsername(), factorContext.getMfaSessionId(), factorContext.getCurrentState());
            } else {
                // MFA 플로우를 위한 경로로 설정된 OttForwardingFilter인데 FactorContext가 없는 경우
                // (예: filterProcessesGetUrl이 "/login/mfa-ott"인데 세션이 만료되었거나 없는 경우)
                // 이 경우, 해당 MFA 흐름은 진행될 수 없으므로 로그인 페이지로 보내는 것이 적절.
                // 어떤 경로가 "MFA용"인지 이 필터가 인지해야 함 (예: filterProcessesGetUrl 경로 패턴 분석)
                String currentPath = request.getRequestURI().toLowerCase();
                if (currentPath.contains("/mfa/") || currentPath.contains("-mfa-")) { // 경로에 "mfa"가 포함되면 MFA 플로우로 간주 (단순 예시)
                    log.warn("OttForwardingFilter: No FactorContext found for an MFA-specific OTT path ({}). This might indicate a session issue or incorrect flow. Redirecting to login.", request.getRequestURI());
                    response.sendRedirect(request.getContextPath() + "/loginForm?error=mfa_session_not_found_for_ott_link_forward");
                    return;
                }
                // 단일 인증 OTT인데 FactorContext가 없는 것은 정상일 수 있음.
                log.debug("OttForwardingFilter: No FactorContext found, assuming single OTT flow for path {}.", request.getRequestURI());
            }
        }

        log.info("OttForwardingFilter: Successfully consumed code '{}' for user '{}'. Preparing auto-POST form to target URL [{}].",
                code, usernameFromOtt, this.ottProcessingUrl);

        // CSRF 토큰 가져오기
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken == null) {
            csrfToken = (CsrfToken) request.getAttribute("_csrf"); // Spring Security 기본 attribute 이름
        }

        // 자동 POST 제출 HTML 생성
        response.setContentType("text/html;charset=" + StandardCharsets.UTF_8.name());
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache"); // HTTP 1.0
        response.setDateHeader("Expires", 0); // 프록시 서버 캐시 방지

        try (PrintWriter writer = response.getWriter()) {
            writer.println("<!DOCTYPE html>");
            writer.println("<html lang=\"ko\">");
            writer.println("<head>");
            writer.println("    <meta charset=\"UTF-8\">");
            writer.println("    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">");
            writer.println("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            writer.println("    <title>OTT 인증 처리 중...</title>");
            writer.println("    <style>");
            writer.println("        body { display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f0f2f5; color: #333; text-align: center; }");
            writer.println("        .spinner { border: 5px solid #f3f3f3; border-top: 5px solid #3498db; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin-bottom: 20px; }");
            writer.println("        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }");
            writer.println("        .message { font-size: 1.1em; }");
            writer.println("        noscript p { color: red; margin-bottom: 10px; }");
            writer.println("        noscript button { padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }");
            writer.println("    </style>");
            writer.println("</head>");
            writer.println("<body>");
            writer.println("    <div class=\"spinner\"></div>");
            writer.println("    <p class=\"message\">인증 정보를 안전하게 전송 중입니다. 잠시만 기다려주세요...</p>");
            // action URL은 contextPath를 포함해야 함
            writer.println("    <form id=\"ottForwardForm\" method=\"POST\" action=\"" + request.getContextPath() + HtmlUtils.htmlEscape(this.ottProcessingUrl) + "\" style=\"display:none;\">");
            writer.println("        <input type=\"hidden\" name=\"" + HtmlUtils.htmlEscape(this.usernameParameterName) + "\" value=\"" + HtmlUtils.htmlEscape(usernameFromOtt) + "\"/>");
            writer.println("        <input type=\"hidden\" name=\"" + HtmlUtils.htmlEscape(this.tokenParameterName) + "\" value=\"" + HtmlUtils.htmlEscape(tokenValueFromOtt) + "\"/>");
            if (csrfToken != null) {
                writer.println("        <input type=\"hidden\" name=\"" + HtmlUtils.htmlEscape(csrfToken.getParameterName()) + "\" value=\"" + HtmlUtils.htmlEscape(csrfToken.getToken()) + "\"/>");
                log.debug("OttForwardingFilter: CSRF token included in auto-POST form. ParameterName: {}, Token available: {}", csrfToken.getParameterName(), StringUtils.hasText(csrfToken.getToken()));
            } else {
                log.warn("OttForwardingFilter: CsrfToken not found in request attributes for POST to {}. CSRF protection might block the request if enabled.", this.ottProcessingUrl);
            }
            writer.println("        <noscript>");
            writer.println("            <p>JavaScript가 비활성화되어 자동 로그인을 진행할 수 없습니다.<br/>이메일의 링크를 다시 클릭하시거나, 문제가 지속되면 관리자에게 문의해주세요.</p>");
            writer.println("            <button type=\"submit\" style=\"padding:10px 20px;background-color:#007bff;color:white;border:none;border-radius:4px;cursor:pointer;display:block;margin:20px auto;\">수동으로 로그인 계속</button>");
            writer.println("        </noscript>");
            writer.println("    </form>");
            writer.println("    <script type=\"text/javascript\">");
            writer.println("        try {");
            writer.println("            document.getElementById('ottForwardForm').submit();");
            writer.println("        } catch(e) {");
            writer.println("            console.error('Auto-submit failed:', e);");
            writer.println("            var errorMsg = document.createElement('p');");
            writer.println("            errorMsg.style.color = 'red';");
            writer.println("            errorMsg.style.textAlign = 'center';");
            writer.println("            errorMsg.style.fontSize = '1.2em';");
            writer.println("            errorMsg.textContent = '자동 제출에 실패했습니다. 페이지를 새로고침하거나 이메일의 링크를 다시 시도해주세요. 문제가 지속되면 관리자에게 문의하세요.';");
            writer.println("            var body = document.body;");
            writer.println("            body.innerHTML = ''; body.appendChild(errorMsg);"); // 기존 내용 지우고 에러 메시지만 표시
            writer.println("        }");
            writer.println("    </script>");
            writer.println("</body></html>");
        }
    }

    private String buildRedirectUrlWithReason(HttpServletRequest request, String baseUrl, String reason) {
        String contextPath = request.getContextPath();
        // baseUrl에 이미 쿼리 파라미터가 있는지 확인하여 올바른 구분자 사용
        String separator = baseUrl.contains("?") ? "&" : "?";
        // reason 값도 URL 인코딩 (혹시 모를 특수문자 대비)
        return contextPath + baseUrl + separator + "reason=" + HtmlUtils.htmlEscape(reason);
    }
}