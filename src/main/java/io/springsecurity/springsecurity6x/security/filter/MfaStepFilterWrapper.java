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

@Slf4j
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    private final ContextPersistence contextPersistence;
    private final RequestMatcher mfaFactorProcessingMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

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

        FactorContext ctx = contextPersistence.contextLoad(request);

        if (!isValidFactorProcessingContext(ctx)) {
            log.warn("Invalid context for MFA factor processing. URI: {}, State: {}, Factor: {}",
                    request.getRequestURI(),
                    ctx != null ? ctx.getCurrentState() : "null",
                    ctx != null ? ctx.getCurrentProcessingFactor() : "null");

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid MFA step or session");
            }
            return;
        }

        // State Machine에 SUBMIT_FACTOR_CREDENTIAL 이벤트 전송
        boolean accepted = stateMachineIntegrator.sendEvent(
                MfaEvent.SUBMIT_FACTOR_CREDENTIAL, ctx, request);

        if (!accepted) {
            log.error("State Machine rejected SUBMIT_FACTOR_CREDENTIAL event for session: {} in state: {}",
                    ctx.getMfaSessionId(), ctx.getCurrentState());

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

            // FilterChain 래퍼로 State Machine 이벤트 처리 통합
            FilterChain wrappedChain = new StateMachineAwareFilterChain(
                    chain, ctx, request, stateMachineIntegrator);

            delegateFactorFilter.doFilter(request, response, wrappedChain);
        } else {
            log.error("No delegate filter found for factorIdentifier: {}", factorIdentifier);

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
     * State Machine을 인식하는 FilterChain 래퍼
     */
    private static class StateMachineAwareFilterChain implements FilterChain {
        private final FilterChain delegate;
        private final FactorContext context;
        private final HttpServletRequest request;
        private final MfaStateMachineIntegrator stateMachineIntegrator;

        public StateMachineAwareFilterChain(FilterChain delegate, FactorContext context,
                                            HttpServletRequest request,
                                            MfaStateMachineIntegrator stateMachineIntegrator) {
            this.delegate = delegate;
            this.context = context;
            this.request = request;
            this.stateMachineIntegrator = stateMachineIntegrator;
        }

        @Override
        public void doFilter(jakarta.servlet.ServletRequest request,
                             jakarta.servlet.ServletResponse response)
                throws IOException, ServletException {

            HttpServletResponse httpResponse = (HttpServletResponse) response;

            // 필터 실행 전 상태
            MfaState beforeState = context.getCurrentState();

            // 실제 필터 실행
            delegate.doFilter(request, response);

            // 필터 실행 후 상태 확인 및 이벤트 전송
            if (!httpResponse.isCommitted()) {
                // 응답이 커밋되지 않았다면 실패로 간주
                if (beforeState == context.getCurrentState()) {
                    // 상태가 변경되지 않았다면 검증 실패
                    stateMachineIntegrator.sendEvent(
                            MfaEvent.FACTOR_VERIFICATION_FAILED, context, this.request);
                }
            }
        }
    }
}