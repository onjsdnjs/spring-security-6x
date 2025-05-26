package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaRequestHandler;
import io.springsecurity.springsecurity6x.security.filter.handler.StateMachineAwareMfaRequestHandler;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaRequestType;
import io.springsecurity.springsecurity6x.security.filter.matcher.MfaUrlMatcher;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 완전 일원화된 MfaContinuationFilter
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine에서 직접 컨텍스트 로드
 */
@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    // ContextPersistence 완전 제거
    private final MfaStateMachineService stateMachineService; // State Machine Service만 사용
    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final RequestMatcher requestMatcher;
    private final MfaRequestHandler requestHandler;
    private final MfaUrlMatcher urlMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public MfaContinuationFilter(MfaStateMachineService stateMachineService, // ContextPersistence 대신 사용
                                 MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 ApplicationContext applicationContext) {
        this.stateMachineService = Objects.requireNonNull(stateMachineService);
        this.mfaPolicyProvider = Objects.requireNonNull(mfaPolicyProvider);
        this.authContextProperties = Objects.requireNonNull(authContextProperties);
        this.responseWriter = Objects.requireNonNull(responseWriter);
        this.applicationContext = Objects.requireNonNull(applicationContext);

        // URL 매처 초기화
        this.urlMatcher = new MfaUrlMatcher(authContextProperties, applicationContext);
        this.requestMatcher = urlMatcher.createRequestMatcher();

        // State Machine 통합자 초기화
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        // 요청 핸들러 초기화 - State Machine 통합자 추가
        this.requestHandler = new StateMachineAwareMfaRequestHandler(
                mfaPolicyProvider,
                authContextProperties,
                responseWriter,
                applicationContext,
                urlMatcher,
                stateMachineIntegrator
        );

        log.info("MfaContinuationFilter initialized with unified State Machine Service");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!urlMatcher.isMfaRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing request: {} {}",
                request.getMethod(), request.getRequestURI());

        // 완전 일원화: State Machine에서만 FactorContext 로드
        FactorContext ctx = loadFactorContextFromStateMachine(request);
        if (!isValidMfaContext(ctx)) {
            handleInvalidContext(request, response);
            return;
        }

        // State Machine 초기화 및 동기화 (필요한 경우에만)
        ensureStateMachineInitialized(ctx, request);

        if (ctx.getCurrentState().isTerminal()) {
            requestHandler.handleTerminalContext(request, response, ctx);
            return;
        }

        try {
            MfaRequestType requestType = urlMatcher.getRequestType(request);

            // State Machine 통합된 요청 처리
            requestHandler.handleRequest(requestType, request, response, ctx, filterChain);

        } catch (Exception e) {
            requestHandler.handleGenericError(request, response, ctx, e);
        }
    }

    /**
     * 완전 일원화: State Machine에서만 FactorContext 로드
     */
    private FactorContext loadFactorContextFromStateMachine(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.trace("No HttpSession found for request. Cannot load FactorContext.");
            return null;
        }

        String mfaSessionId = (String) session.getAttribute("MFA_SESSION_ID");
        if (mfaSessionId == null) {
            log.trace("No MFA session ID found in session. Cannot load FactorContext.");
            return null;
        }

        try {
            // State Machine에서 직접 로드 (일원화)
            FactorContext context = stateMachineIntegrator.loadFactorContext(mfaSessionId);

            if (context != null) {
                // 마지막 활동 시간 업데이트
                context.updateLastActivityTimestamp();

                // State Machine에 저장 (활동 시간 업데이트 반영)
                stateMachineIntegrator.saveFactorContext(context);

                log.debug("FactorContext loaded from unified State Machine: sessionId={}, state={}",
                        context.getMfaSessionId(), context.getCurrentState());
            } else {
                log.debug("No FactorContext found in State Machine for session: {}", mfaSessionId);
            }

            return context;
        } catch (Exception e) {
            log.error("Failed to load FactorContext from State Machine for session: {}", mfaSessionId, e);
            return null;
        }
    }

    /**
     * 완전 일원화: State Machine 초기화 보장
     */
    private void ensureStateMachineInitialized(FactorContext ctx, HttpServletRequest request) {
        try {
            // State Machine과 동기화
            stateMachineIntegrator.syncStateWithStateMachine(ctx, request);
        } catch (Exception e) {
            log.warn("Failed to sync with State Machine for session: {}", ctx.getMfaSessionId(), e);
        }
    }

    private boolean isValidMfaContext(FactorContext ctx) {
        return ctx != null &&
                ctx.getMfaSessionId() != null &&
                "MFA".equalsIgnoreCase(ctx.getFlowTypeName());
    }

    private void handleInvalidContext(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        log.warn("Invalid MFA context for request: {}", request.getRequestURI());

        // 세션에서 잘못된 MFA 세션 ID 정리
        HttpSession session = request.getSession(false);
        if (session != null) {
            String oldSessionId = (String) session.getAttribute("MFA_SESSION_ID");
            if (oldSessionId != null) {
                // State Machine 정리
                try {
                    stateMachineService.releaseStateMachine(oldSessionId);
                } catch (Exception e) {
                    log.warn("Failed to release invalid State Machine session: {}", oldSessionId, e);
                }
                session.removeAttribute("MFA_SESSION_ID");
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_SESSION_INVALID");
        errorResponse.put("message", "MFA 세션이 유효하지 않습니다.");
        errorResponse.put("redirectUrl", request.getContextPath() + "/loginForm");

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_SESSION_INVALID", "MFA 세션이 유효하지 않습니다.",
                request.getRequestURI(), errorResponse);
    }
}