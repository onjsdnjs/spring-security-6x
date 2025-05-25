package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaUrlMatcher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class MfaRequestHandler {

    private final ContextPersistence contextPersistence;
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final MfaUrlMatcher urlMatcher;

    public void handleRequest(MfaRequestType requestType, HttpServletRequest request,
                              HttpServletResponse response, FactorContext ctx,
                              FilterChain filterChain) throws IOException, ServletException {

        log.debug("Handling {} request for session: {}", requestType, ctx.getMfaSessionId());

        switch (requestType) {
            case MFA_INITIATE:
                handleMfaInitiate(request, response, ctx);
                break;

            case SELECT_FACTOR:
                handleSelectFactor(request, response, ctx);
                break;

            case TOKEN_GENERATION:
            case LOGIN_PROCESSING:
                // 이런 요청들은 다른 필터로 위임
                filterChain.doFilter(request, response);
                break;

            default:
                log.warn("Unhandled request type: {} for session: {}",
                        requestType, ctx.getMfaSessionId());
                filterChain.doFilter(request, response);
        }
    }

    private void handleMfaInitiate(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext ctx) throws IOException {
        // MFA 시작 페이지 렌더링 또는 리다이렉트
        String selectFactorUrl = request.getContextPath() +
                authContextProperties.getMfa().getSelectFactorUrl();
        response.sendRedirect(selectFactorUrl);
    }

    private void handleSelectFactor(HttpServletRequest request, HttpServletResponse response,
                                    FactorContext ctx) throws IOException {
        // 팩터 선택 페이지는 컨트롤러에서 처리하므로 패스
        // 실제로는 이 필터가 처리하지 않고 컨트롤러로 전달됨
    }

    public void handleInvalidContext(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        log.warn("Invalid MFA context for request: {}", request.getRequestURI());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_SESSION_INVALID");
        errorResponse.put("message", "MFA 세션이 유효하지 않습니다.");
        errorResponse.put("redirectUrl", request.getContextPath() + "/loginForm");

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다.",
                request.getRequestURI(), errorResponse);
    }

    public void handleTerminalContext(HttpServletRequest request, HttpServletResponse response,
                                      FactorContext ctx) throws IOException {
        log.warn("Terminal state {} accessed for session: {}",
                ctx.getCurrentState(), ctx.getMfaSessionId());

        String message = switch (ctx.getCurrentState()) {
            case MFA_SUCCESSFUL -> "MFA 인증이 이미 완료되었습니다.";
            case MFA_FAILED_TERMINAL -> "MFA 인증이 실패했습니다.";
            case MFA_SESSION_EXPIRED -> "MFA 세션이 만료되었습니다.";
            case MFA_CANCELLED -> "MFA 인증이 취소되었습니다.";
            default -> "MFA 인증을 진행할 수 없습니다.";
        };

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                "MFA_TERMINAL_STATE", message, request.getRequestURI());
    }

    public void handleGenericError(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext ctx, Exception e) throws IOException {
        log.error("Error processing MFA request for session: {}",
                ctx.getMfaSessionId(), e);

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_PROCESSING_ERROR", "MFA 처리 중 오류가 발생했습니다.",
                request.getRequestURI());
    }
}