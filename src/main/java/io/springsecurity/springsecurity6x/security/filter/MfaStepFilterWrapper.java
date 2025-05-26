package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorIdentifier;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.statemachine.core.service.MfaStateMachineService;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
import jakarta.servlet.Filter;
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
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * 완전 일원화된 MfaStepFilterWrapper
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - FilterChain 래퍼도 State Machine Service 사용
 */
@Slf4j
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    // ContextPersistence 완전 제거
    private final MfaStateMachineService stateMachineService; // State Machine Service만 사용
    private final RequestMatcher mfaFactorProcessingMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    // 보안 강화를 위한 추가 필드
    private static final int MAX_VERIFICATION_ATTEMPTS = 5;
    private static final long VERIFICATION_TIMEOUT = TimeUnit.MINUTES.toMillis(5);
    public static final long MIN_VERIFICATION_DELAY = 500;

    public MfaStepFilterWrapper(ConfiguredFactorFilterProvider configuredFactorFilterProvider,
                                MfaStateMachineService stateMachineService, // ContextPersistence 대신 사용
                                RequestMatcher mfaFactorProcessingMatcher,
                                ApplicationContext applicationContext) {
        this.configuredFactorFilterProvider = Objects.requireNonNull(configuredFactorFilterProvider);
        this.stateMachineService = Objects.requireNonNull(stateMachineService);
        this.mfaFactorProcessingMatcher = Objects.requireNonNull(mfaFactorProcessingMatcher);

        // State Machine 통합자 가져오기
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        log.info("MfaStepFilterWrapper initialized with unified State Machine Service");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        if (!this.mfaFactorProcessingMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        log.debug("MfaStepFilterWrapper processing factor submission request: {}",
                request.getRequestURI());

        long startTime = System.currentTimeMillis();

        // 완전 일원화: State Machine에서만 FactorContext 로드
        FactorContext ctx = loadFactorContextFromStateMachine(request);

        if (!isValidFactorProcessingContext(ctx)) {
            log.warn("Invalid context for MFA factor processing. URI: {}, State: {}, Factor: {}",
                    request.getRequestURI(),
                    ctx != null ? ctx.getCurrentState() : "null",
                    ctx != null ? ctx.getCurrentProcessingFactor() : "null");

            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid MFA step or session");
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

        // State Machine에 SUBMIT_FACTOR_CREDENTIAL 이벤트 전송
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
            log.info("Delegating MFA factor processing for {} to filter: {}",
                    factorIdentifier, delegateFactorFilter.getClass().getName());

            // 검증 시작 시간 기록
            ctx.setAttribute("verificationStartTime", System.currentTimeMillis());

            // State Machine에 저장 (일원화)
            stateMachineService.saveFactorContext(ctx);

            // FilterChain 래퍼로 State Machine 이벤트 처리 통합
            FilterChain wrappedChain = new UnifiedStateMachineAwareFilterChain(
                    chain, ctx, request, stateMachineIntegrator, startTime, stateMachineService); // ContextPersistence 대신 사용

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
            // State Machine 에서 직접 로드 (일원화)
            return stateMachineIntegrator.loadFactorContext(mfaSessionId);
        } catch (Exception e) {
            log.error("Failed to load FactorContext from State Machine for session: {}", mfaSessionId, e);
            return null;
        }
    }

    private boolean isValidFactorProcessingContext(FactorContext ctx) {
        return ctx != null &&
                ctx.getCurrentProcessingFactor() != null &&
                ctx.getCurrentState() == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION &&
                ctx.getFlowTypeName() != null &&
                ctx.getCurrentStepId() != null;
    }

    private boolean isSessionExpired(FactorContext ctx) {
        Object challengeStartTime = ctx.getAttribute("challengeInitiatedAt");
        if (challengeStartTime instanceof Long) {
            long elapsed = System.currentTimeMillis() - (Long) challengeStartTime;
            return elapsed > VERIFICATION_TIMEOUT;
        }
        return false;
    }

    private boolean isRetryLimitExceeded(FactorContext ctx) {
        int attempts = ctx.getAttemptCount(ctx.getCurrentProcessingFactor());
        return attempts >= MAX_VERIFICATION_ATTEMPTS;
    }

    private void ensureMinimumDelay(long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed < MIN_VERIFICATION_DELAY) {
            try {
                Thread.sleep(MIN_VERIFICATION_DELAY - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 완전 일원화된 State Machine 인식 FilterChain 래퍼
     * - ContextPersistence 제거하고 MfaStateMachineService만 사용
     */
    private static class UnifiedStateMachineAwareFilterChain implements FilterChain {
        private final FilterChain delegate;
        private final FactorContext context;
        private final HttpServletRequest request;
        private final MfaStateMachineIntegrator stateMachineIntegrator;
        private final long startTime;
        private final MfaStateMachineService stateMachineService; // ContextPersistence 대신 사용

        public UnifiedStateMachineAwareFilterChain(FilterChain delegate, FactorContext context,
                                                   HttpServletRequest request,
                                                   MfaStateMachineIntegrator stateMachineIntegrator,
                                                   long startTime,
                                                   MfaStateMachineService stateMachineService) { // ContextPersistence 대신 사용
            this.delegate = delegate;
            this.context = context;
            this.request = request;
            this.stateMachineIntegrator = stateMachineIntegrator;
            this.startTime = startTime;
            this.stateMachineService = stateMachineService;
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

                // State Machine 에만 저장 (일원화)
                stateMachineIntegrator.saveFactorContext(context);

                // 필터 실행 후 상태 확인 및 이벤트 전송
                if (!httpResponse.isCommitted()) {
                    // 응답이 커밋되지 않았다면 실패로 간주
                    if (beforeState == context.getCurrentState()) {
                        // 상태가 변경되지 않았다면 검증 실패
                        stateMachineIntegrator.sendEvent(
                                MfaEvent.FACTOR_VERIFICATION_FAILED, context, this.request);
                    }
                }
            } catch (Exception e) {
                // 예외 발생 시 실패 이벤트 전송
                log.error("Error during factor verification", e);
                stateMachineIntegrator.sendEvent(
                        MfaEvent.FACTOR_VERIFICATION_FAILED, context, this.request);
                throw e;
            } finally {
                // 최소 지연 보장
                ensureMinimumDelay(startTime);
            }
        }

        private void ensureMinimumDelay(long startTime) {
            long elapsed = System.currentTimeMillis() - startTime;
            if (elapsed < MIN_VERIFICATION_DELAY) {
                try {
                    Thread.sleep(MIN_VERIFICATION_DELAY - elapsed);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}