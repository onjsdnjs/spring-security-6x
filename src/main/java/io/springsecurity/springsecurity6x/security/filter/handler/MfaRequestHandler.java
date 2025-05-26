package io.springsecurity.springsecurity6x.security.filter.handler;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaUrlMatcher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Getter
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

        log.debug("Handling {} request for session: {} in state: {}",
                requestType, ctx.getMfaSessionId(), ctx.getCurrentState());

        switch (requestType) {
            case MFA_INITIATE:
                handleMfaInitiate(request, response, ctx);
                break;

            case SELECT_FACTOR:
                handleSelectFactor(request, response, ctx);
                break;

            case TOKEN_GENERATION:
                handleTokenGeneration(request, response, ctx, filterChain);
                break;

            case LOGIN_PROCESSING:
                // 실제 인증 처리는 다른 필터로 위임
                filterChain.doFilter(request, response);
                break;

            default:
                log.warn("Unhandled request type: {} for session: {}",
                        requestType, ctx.getMfaSessionId());
                filterChain.doFilter(request, response);
        }
    }

    protected void handleMfaInitiate(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext ctx) throws IOException {
        MfaState currentState = ctx.getCurrentState();

        if (currentState == MfaState.AWAITING_FACTOR_SELECTION) {
            String selectFactorUrl = request.getContextPath() +
                    authContextProperties.getMfa().getSelectFactorUrl();
            response.sendRedirect(selectFactorUrl);
        } else if (currentState == MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION) {
            String challengeUrl = determineChalllengeUrl(ctx, request);
            response.sendRedirect(challengeUrl);
        } else {
            log.warn("Unexpected state {} for MFA initiate request", currentState);
            handleInvalidState(request, response, ctx);
        }
    }

    protected void handleSelectFactor(HttpServletRequest request, HttpServletResponse response,
                                    FactorContext ctx) throws IOException {
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_SELECTION) {
            log.warn("Invalid state {} for factor selection", ctx.getCurrentState());
            handleInvalidState(request, response, ctx);
            return;
        }

        // 실제 렌더링은 컨트롤러에서 처리하므로 패스
    }

    protected void handleTokenGeneration(HttpServletRequest request, HttpServletResponse response,
                                       FactorContext ctx, FilterChain filterChain)
            throws IOException, ServletException {
        if (ctx.getCurrentState() != MfaState.AWAITING_FACTOR_CHALLENGE_INITIATION &&
                ctx.getCurrentState() != MfaState.FACTOR_CHALLENGE_INITIATED) {
            log.warn("Invalid state {} for token generation", ctx.getCurrentState());
            handleInvalidState(request, response, ctx);
            return;
        }

        // 실제 토큰 생성은 다음 필터에서 처리
        filterChain.doFilter(request, response);
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

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("currentState", ctx.getCurrentState().name());
        errorResponse.put("isTerminal", true);

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                "MFA_TERMINAL_STATE", message, request.getRequestURI(), errorResponse);
    }

    protected void handleInvalidStateTransition(HttpServletRequest request, HttpServletResponse response,
                                             FactorContext ctx, MfaEvent event) throws IOException {
        log.error("Invalid state transition: {} -> {} for session: {}",
                ctx.getCurrentState(), event, ctx.getMfaSessionId());

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "INVALID_STATE_TRANSITION");
        errorResponse.put("message", "현재 상태에서 요청한 작업을 수행할 수 없습니다.");
        errorResponse.put("currentState", ctx.getCurrentState().name());
        errorResponse.put("attemptedEvent", event.name());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "INVALID_STATE_TRANSITION", "잘못된 상태 전이",
                request.getRequestURI(), errorResponse);
    }

    public void handleGenericError(HttpServletRequest request, HttpServletResponse response,
                                   FactorContext ctx, Exception e) throws IOException {
        log.error("Error processing MFA request for session: {}",
                ctx.getMfaSessionId(), e);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_PROCESSING_ERROR");
        errorResponse.put("message", "MFA 처리 중 오류가 발생했습니다.");
        if (ctx != null) {
            errorResponse.put("currentState", ctx.getCurrentState().name());
            errorResponse.put("errorType", e.getClass().getSimpleName());
        }

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_PROCESSING_ERROR", "MFA 처리 중 오류가 발생했습니다.",
                request.getRequestURI(), errorResponse);
    }

    protected void handleInvalidState(HttpServletRequest request, HttpServletResponse response,
                                    FactorContext ctx) throws IOException {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "INVALID_STATE");
        errorResponse.put("message", "잘못된 MFA 상태입니다.");
        errorResponse.put("currentState", ctx.getCurrentState().name());
        errorResponse.put("redirectUrl", request.getContextPath() + "/mfa/select-factor");

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "INVALID_STATE", "잘못된 MFA 상태",
                request.getRequestURI(), errorResponse);
    }

    protected String determineChalllengeUrl(FactorContext ctx, HttpServletRequest request) {
        if (ctx.getCurrentProcessingFactor() == null) {
            return request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        }

        return switch (ctx.getCurrentProcessingFactor()) {
            case OTT -> request.getContextPath() +
                    authContextProperties.getMfa().getOttFactor().getRequestCodeUiUrl();
            case PASSKEY -> request.getContextPath() +
                    authContextProperties.getMfa().getPasskeyFactor().getChallengeUrl();
            default -> request.getContextPath() + authContextProperties.getMfa().getSelectFactorUrl();
        };
    }
}