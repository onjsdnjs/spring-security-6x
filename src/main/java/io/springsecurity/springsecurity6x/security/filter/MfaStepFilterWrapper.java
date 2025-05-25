package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorIdentifier;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaEvent;
import io.springsecurity.springsecurity6x.security.statemachine.enums.MfaState;
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
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Slf4j
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    private final ContextPersistence contextPersistence;
    private final RequestMatcher mfaFactorProcessingMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    // 보안 강화를 위한 추가 필드
    private static final int MAX_VERIFICATION_ATTEMPTS = 5;
    private static final long VERIFICATION_TIMEOUT = TimeUnit.MINUTES.toMillis(5);
    private static final long MIN_VERIFICATION_DELAY = 500; // 최소 검증 지연 (밀리초)

    public MfaStepFilterWrapper(ConfiguredFactorFilterProvider configuredFactorFilterProvider,
                                ContextPersistence contextPersistence,
                                RequestMatcher mfaFactorProcessingMatcher,
                                ApplicationContext applicationContext) {
        this.configuredFactorFilterProvider = Objects.requireNonNull(configuredFactorFilterProvider);
        this.contextPersistence = Objects.requireNonNull(contextPersistence);
        this.mfaFactorProcessingMatcher = Objects.requireNonNull(mfaFactorProcessingMatcher);

        // State Machine 통합자 가져오기
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        log.info("MfaStepFilterWrapper initialized with State Machine integration");
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

        // 타이밍 공격 방지를 위한 시작 시간 기록
        long startTime = System.currentTimeMillis();

        FactorContext ctx = contextPersistence.contextLoad(request);

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

        // 세션 타임아웃 확인
        if (isSessionExpired(ctx)) {
            log.warn("MFA session expired for session: {}", ctx.getMfaSessionId());

            stateMachineIntegrator.sendEvent(MfaEvent.SESSION_TIMEOUT, ctx, request);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        "MFA session expired");
            }
            return;
        }

        // 재시도 횟수 확인
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

            // FilterChain 래퍼로 State Machine 이벤트 처리 통합
            FilterChain wrappedChain = new SecureStateMachineAwareFilterChain(
                    chain, ctx, request, stateMachineIntegrator, startTime);

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
     * 세션 만료 확인
     */
    private boolean isSessionExpired(FactorContext ctx) {
        Object challengeStartTime = ctx.getAttribute("challengeInitiatedAt");
        if (challengeStartTime instanceof Long) {
            long elapsed = System.currentTimeMillis() - (Long) challengeStartTime;
            return elapsed > VERIFICATION_TIMEOUT;
        }
        return false;
    }

    /**
     * 재시도 한계 초과 확인
     */
    private boolean isRetryLimitExceeded(FactorContext ctx) {
        int attempts = ctx.getAttemptCount(ctx.getCurrentProcessingFactor());
        return attempts >= MAX_VERIFICATION_ATTEMPTS;
    }

    /**
     * 타이밍 공격 방지를 위한 최소 지연 보장
     */
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
     * 보안 강화된 State Machine 인식 FilterChain 래퍼
     */
    private static class SecureStateMachineAwareFilterChain implements FilterChain {
        private final FilterChain delegate;
        private final FactorContext context;
        private final HttpServletRequest request;
        private final MfaStateMachineIntegrator stateMachineIntegrator;
        private final long startTime;

        public SecureStateMachineAwareFilterChain(FilterChain delegate, FactorContext context,
                                                  HttpServletRequest request,
                                                  MfaStateMachineIntegrator stateMachineIntegrator,
                                                  long startTime) {
            this.delegate = delegate;
            this.context = context;
            this.request = request;
            this.stateMachineIntegrator = stateMachineIntegrator;
            this.startTime = startTime;
        }

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request,
                             jakarta.servlet.ServletResponse response)
                throws IOException, ServletException {

            HttpServletResponse httpResponse = (HttpServletResponse) response;

            // 필터 실행 전 상태
            MfaState beforeState = context.getCurrentState();

            try {
                // 실제 필터 실행
                delegate.doFilter(request, response);

                // 검증 시간 기록
                long verificationTime = System.currentTimeMillis() - startTime;
                context.setAttribute("lastVerificationTime", verificationTime);

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