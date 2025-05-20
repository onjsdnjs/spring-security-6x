package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorIdentifier;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Slf4j
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider; // 변경
    private final ContextPersistence contextPersistence;
    private final RequestMatcher mfaFactorProcessingMatcher;

    public MfaStepFilterWrapper(ConfiguredFactorFilterProvider configuredFactorFilterProvider, // 변경
                                ContextPersistence contextPersistence,
                                RequestMatcher mfaFactorProcessingMatcher) {
        this.configuredFactorFilterProvider = Objects.requireNonNull(configuredFactorFilterProvider, "ConfiguredFactorFilterProvider cannot be null.");
        this.contextPersistence = Objects.requireNonNull(contextPersistence, "ContextPersistence cannot be null.");
        this.mfaFactorProcessingMatcher = Objects.requireNonNull(mfaFactorProcessingMatcher, "mfaFactorProcessingMatcher cannot be null for MfaStepFilterWrapper.");
        log.info("MfaStepFilterWrapper initialized. Will process requests matching: {}", mfaFactorProcessingMatcher);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!this.mfaFactorProcessingMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        log.debug("MfaStepFilterWrapper processing factor submission request: {}", request.getRequestURI());

        FactorContext ctx = contextPersistence.contextLoad(request);

        if (ctx == null || ctx.getCurrentProcessingFactor() == null ||
                ctx.getCurrentState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION ||
                ctx.getFlowTypeName() == null || ctx.getCurrentStepId() == null) { // flowTypeName, currentStepId null 체크 추가
            log.warn("MfaStepFilterWrapper: Invalid attempt to process MFA factor. Context/State/Factor/Flow/StepId mismatch. URI: {}, State: {}, CurrentFactor: {}, Flow: {}, StepId: {}. SessionId: {}",
                    request.getRequestURI(),
                    (ctx != null ? ctx.getCurrentState() : "N/A"),
                    (ctx != null ? ctx.getCurrentProcessingFactor() : "N/A"),
                    (ctx != null ? ctx.getFlowTypeName() : "N/A"),
                    (ctx != null ? ctx.getCurrentStepId() : "N/A"),
                    (ctx != null ? ctx.getMfaSessionId() : "N/A"));
            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid MFA step, session, or missing flow/step identifier.");
            }
            return;
        }

        FactorIdentifier factorIdentifier = FactorIdentifier.of(ctx.getFlowTypeName(), ctx.getCurrentStepId());

        Filter delegateFactorFilter = configuredFactorFilterProvider.getFilter(factorIdentifier);

        if (delegateFactorFilter != null) {
            log.info("MfaStepFilterWrapper: Delegating MFA step processing for factorIdentifier '{}' (type: {}) to filter: {}. Session: {}",
                    factorIdentifier, ctx.getCurrentProcessingFactor(), delegateFactorFilter.getClass().getName(), ctx.getMfaSessionId());
            delegateFactorFilter.doFilter(request, response, chain);
            return;
        } else {
            log.error("MfaStepFilterWrapper: No delegate filter found in ConfiguredFactorFilterProvider for factorIdentifier: '{}' (type: {}). Critical configuration error. Session: {}",
                    factorIdentifier, ctx.getCurrentProcessingFactor(), ctx.getMfaSessionId());
            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA factor processing misconfiguration for " + ctx.getCurrentProcessingFactor());
            }
            return;
        }
    }
}

