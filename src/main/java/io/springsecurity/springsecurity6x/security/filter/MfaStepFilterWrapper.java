package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorIdentifier;
import io.springsecurity.springsecurity6x.security.core.session.MfaSessionRepository;
import io.springsecurity.springsecurity6x.security.core.validator.MfaContextValidator;
import io.springsecurity.springsecurity6x.security.core.validator.ValidationResult;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.properties.MfaSettings;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import io.springsecurity.springsecurity6x.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 완전 일원화된 MfaStepFilterWrapper
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - FilterChain 래퍼도 State Machine Service 사용
 */
@Slf4j
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    private final RequestMatcher mfaFactorProcessingMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final MfaSettings mfaSettings;
    private final AuthResponseWriter responseWriter;

    public MfaStepFilterWrapper(ConfiguredFactorFilterProvider configuredFactorFilterProvider,
                                RequestMatcher mfaFactorProcessingMatcher,
                                ApplicationContext applicationContext,
                                AuthContextProperties authContextProperties, AuthResponseWriter responseWriter) {
        this.configuredFactorFilterProvider = Objects.requireNonNull(configuredFactorFilterProvider);
        this.mfaFactorProcessingMatcher = Objects.requireNonNull(mfaFactorProcessingMatcher);
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);
        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);
        this.mfaSettings = authContextProperties.getMfa();
        this.responseWriter = responseWriter;

        log.info("MfaStepFilterWrapper initialized with {} repository",
                sessionRepository.getRepositoryType());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        if (!this.mfaFactorProcessingMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        log.debug("MfaStepFilterWrapper processing factor submission request: {} using {} repository",
                request.getRequestURI(), sessionRepository.getRepositoryType());

        long startTime = System.currentTimeMillis();

        // ✅ 개선: 통합된 검증 로직 사용
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        ValidationResult validation = MfaContextValidator.validateFactorProcessingContext(ctx, sessionRepository);

        if (validation.hasErrors()) {
            log.warn("Invalid context for MFA factor processing using {} repository. URI: {}, Errors: {}",
                    sessionRepository.getRepositoryType(), request.getRequestURI(), validation.getErrors());

            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("errors", validation.getErrors());
                errorResponse.put("warnings", validation.getWarnings());
                errorResponse.put("repositoryType", sessionRepository.getRepositoryType());

                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "INVALID_MFA_CONTEXT", String.join(", ", validation.getErrors()),
                        request.getRequestURI(), errorResponse);
            }
            return;
        }

        // 경고 로깅
        if (validation.hasWarnings()) {
            log.warn("MFA factor processing warnings: {}", validation.getWarnings());
        }

        // 개선: Repository를 통한 세션 검증
        if (!sessionRepository.existsSession(ctx.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during factor processing",
                    ctx.getMfaSessionId(), sessionRepository.getRepositoryType());
            ensureMinimumDelay(startTime);
            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Session not found");
            }
            return;
        }

        // 세션 타임아웃 및 재시도 한계 확인
        if (isSessionExpired(ctx)) {
            log.warn("MFA session expired for session: {}", ctx.getMfaSessionId());
            stateMachineIntegrator.sendEvent(MfaEvent.SESSION_TIMEOUT, ctx, request);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "MFA session expired");
            }
            return;
        }

        if (isRetryLimitExceeded(ctx)) {
            log.warn("Retry limit exceeded for session: {}", ctx.getMfaSessionId());
            stateMachineIntegrator.sendEvent(MfaEvent.RETRY_LIMIT_EXCEEDED, ctx, request);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        "Maximum verification attempts exceeded");
            }
            return;
        }

        boolean accepted = stateMachineIntegrator.sendEvent(
                MfaEvent.SUBMIT_FACTOR_CREDENTIAL, ctx, request);

        if (!accepted) {
            log.error("State Machine rejected SUBMIT_FACTOR_CREDENTIAL event for session: {} in state: {}",
                    ctx.getMfaSessionId(), ctx.getCurrentState());

            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid state for factor verification");
            }
            return;
        }

        FactorIdentifier factorIdentifier = FactorIdentifier.of(
                ctx.getFlowTypeName(), ctx.getCurrentStepId());

        Filter delegateFactorFilter = configuredFactorFilterProvider.getFilter(factorIdentifier);

        if (delegateFactorFilter != null) {
            log.info("Delegating MFA factor processing for {} to filter: {} using {} repository",
                    factorIdentifier, delegateFactorFilter.getClass().getName(),
                    sessionRepository.getRepositoryType());

            ctx.setAttribute("verificationStartTime", System.currentTimeMillis());
            stateMachineIntegrator.saveFactorContext(ctx);

            // FilterChain 래퍼에 Repository 정보 전달
            FilterChain wrappedChain = new RepositoryAwareStateMachineFilterChain(
                    chain, ctx, request, stateMachineIntegrator, sessionRepository, startTime,mfaSettings);

            delegateFactorFilter.doFilter(request, response, wrappedChain);
        } else {
            log.error("No delegate filter found for factorIdentifier: {}", factorIdentifier);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "MFA factor processing misconfiguration");
            }
        }
    }

    private boolean isValidFactorProcessingContext(FactorContext ctx) {
        return ctx != null &&
                ctx.getCurrentProcessingFactor() != null &&
                ctx.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION &&
                ctx.getFlowTypeName() != null &&
                ctx.getCurrentStepId() != null;
    }

    /**
     * 개선: MfaSettings를 활용한 세션 만료 확인 (하드코딩 상수 제거)
     */
    private boolean isSessionExpired(FactorContext ctx) {
        Object challengeStartTime = ctx.getAttribute("challengeInitiatedAt");
        if (challengeStartTime instanceof Long challengeStartTimeMs) {
            // 개선: MfaSettings의 메서드 활용
            return mfaSettings.isChallengeExpired(challengeStartTimeMs);
        }
        return false;
    }

    /**
     * 개선: MfaSettings를 활용한 재시도 한계 확인 (하드코딩 상수 제거)
     */
    private boolean isRetryLimitExceeded(FactorContext ctx) {
        int attempts = ctx.getAttemptCount(ctx.getCurrentProcessingFactor());
        // 개선: MfaSettings의 메서드 활용
        return !mfaSettings.isRetryAllowed(attempts);
    }

    /**
     * 개선: MfaSettings를 활용한 최소 지연 보장 (하드코딩 상수 제거)
     */
    private void ensureMinimumDelay(long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        // 개선: MfaSettings 에서 최소 지연 시간 가져오기
        long minDelayMs = mfaSettings.getMinimumDelayMs();
        if (elapsed < minDelayMs) {
            try {
                Thread.sleep(minDelayMs - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 완전 일원화된 State Machine 인식 FilterChain 래퍼
     * - ContextPersistence 제거하고 MfaStateMachineService만 사용
     */
    private static class RepositoryAwareStateMachineFilterChain implements FilterChain {
        private final FilterChain delegate;
        private final FactorContext context;
        private final HttpServletRequest request;
        private final MfaStateMachineIntegrator stateMachineIntegrator;
        private final MfaSessionRepository sessionRepository; // 추가: Repository 정보
        private final long startTime;
        private final MfaSettings mfaSettings; // 추가: 설정 정보

        public RepositoryAwareStateMachineFilterChain(FilterChain delegate, FactorContext context,
                                                      HttpServletRequest request,
                                                      MfaStateMachineIntegrator stateMachineIntegrator,
                                                      MfaSessionRepository sessionRepository,
                                                      long startTime, MfaSettings mfaSettings) {
            this.delegate = delegate;
            this.context = context;
            this.request = request;
            this.stateMachineIntegrator = stateMachineIntegrator;
            this.sessionRepository = sessionRepository; // 추가
            this.startTime = startTime;
            this.mfaSettings = mfaSettings;
        }

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request,
                             jakarta.servlet.ServletResponse response)
                throws IOException, ServletException {

            HttpServletResponse httpResponse = (HttpServletResponse) response;
            MfaState beforeState = context.getCurrentState();

            try {
                // 실제 필터 실행
                delegate.doFilter(request, response);

                // 검증 시간 기록
                long verificationTime = System.currentTimeMillis() - startTime;
                context.setAttribute("lastVerificationTime", verificationTime);

                // 개선: Repository를 통한 세션 갱신
                sessionRepository.refreshSession(context.getMfaSessionId());

                stateMachineIntegrator.saveFactorContext(context);

                // 필터 실행 후 상태 확인 및 이벤트 전송
                if (!httpResponse.isCommitted()) {
                    if (beforeState == context.getCurrentState()) {
                        stateMachineIntegrator.sendEvent(
                                MfaEvent.FACTOR_VERIFICATION_FAILED, context, this.request);
                    }
                }
            } catch (Exception e) {
                log.error("Error during factor verification using {} repository",
                        sessionRepository.getRepositoryType(), e);
                stateMachineIntegrator.sendEvent(
                        MfaEvent.FACTOR_VERIFICATION_FAILED, context, this.request);
                throw e;
            } finally {
                ensureMinimumDelay(startTime);
            }
        }

        /**
         * 개선: MfaSettings를 활용한 최소 지연 보장
         */
        private void ensureMinimumDelay(long startTime) {
            long elapsed = System.currentTimeMillis() - startTime;
            // 개선: MfaSettings 에서 최소 지연 시간 가져오기
            long minDelayMs = mfaSettings.getMinimumDelayMs();
            if (elapsed < minDelayMs) {
                try {
                    Thread.sleep(minDelayMs - elapsed);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}