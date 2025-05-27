package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.core.validator.MfaContextValidator;
import io.springsecurity.springsecurity6x.security.core.validator.ValidationResult;
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

    private final MfaPolicyProvider mfaPolicyProvider;
    private final AuthContextProperties authContextProperties;
    private final AuthResponseWriter responseWriter;
    private final ApplicationContext applicationContext;
    private final RequestMatcher requestMatcher;
    private final MfaRequestHandler requestHandler;
    private final MfaUrlMatcher urlMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;

    public MfaContinuationFilter(MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 ApplicationContext applicationContext) {
        this.mfaPolicyProvider = Objects.requireNonNull(mfaPolicyProvider);
        this.authContextProperties = Objects.requireNonNull(authContextProperties);
        this.responseWriter = Objects.requireNonNull(responseWriter);
        this.applicationContext = Objects.requireNonNull(applicationContext);

        this.urlMatcher = new MfaUrlMatcher(authContextProperties, applicationContext);
        this.requestMatcher = urlMatcher.createRequestMatcher();
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);

        this.requestHandler = new StateMachineAwareMfaRequestHandler(
                mfaPolicyProvider,
                authContextProperties,
                responseWriter,
                applicationContext,
                urlMatcher,
                stateMachineIntegrator
        );

        log.info("MfaContinuationFilter initialized with {} repository",
                sessionRepository.getRepositoryType());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!urlMatcher.isMfaRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing request: {} {} using {} repository",
                request.getMethod(), request.getRequestURI(), sessionRepository.getRepositoryType());

        // ✅ 개선: 통합된 검증 로직 사용
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        ValidationResult validation = MfaContextValidator.validateFactorSelectionContext(ctx, sessionRepository);

        if (validation.hasErrors()) {
            log.warn("Invalid MFA context for request: {} - Errors: {}",
                    request.getRequestURI(), validation.getErrors());
            handleInvalidContext(request, response, validation);
            return;
        }

        // 경고 로깅
        if (validation.hasWarnings()) {
            log.warn("MFA context warnings for request: {} - Warnings: {}",
                    request.getRequestURI(), validation.getWarnings());
        }

        ensureStateMachineInitialized(ctx, request);

        if (ctx.getCurrentState().isTerminal()) {
            requestHandler.handleTerminalContext(request, response, ctx);
            return;
        }

        try {
            MfaRequestType requestType = urlMatcher.getRequestType(request);
            requestHandler.handleRequest(requestType, request, response, ctx, filterChain);
        } catch (Exception e) {
            requestHandler.handleGenericError(request, response, ctx, e);
        }
    }

    /**
     * 개선: Repository 패턴 통합 - 무효한 컨텍스트 처리
     */
    private void handleInvalidContext(HttpServletRequest request, HttpServletResponse response,
                                      ValidationResult validation) throws IOException {
        String oldSessionId = sessionRepository.getSessionId(request);
        if (oldSessionId != null) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, response);
            } catch (Exception e) {
                log.warn("Failed to cleanup invalid session: {}", oldSessionId, e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_SESSION_INVALID");
        errorResponse.put("message", "MFA 세션이 유효하지 않습니다.");
        errorResponse.put("errors", validation.getErrors());
        errorResponse.put("warnings", validation.getWarnings());
        errorResponse.put("redirectUrl", request.getContextPath() + "/loginForm");
        errorResponse.put("repositoryType", sessionRepository.getRepositoryType());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_SESSION_INVALID", String.join(", ", validation.getErrors()),
                request.getRequestURI(), errorResponse);
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
}