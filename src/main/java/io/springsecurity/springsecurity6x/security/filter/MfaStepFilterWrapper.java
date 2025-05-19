package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.util.matcher.RequestMatcher; // RequestMatcher import
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Slf4j
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private final FeatureRegistry featureRegistry;
    private final ContextPersistence contextPersistence;
    private final RequestMatcher mfaFactorProcessingMatcher; // 이 필터가 처리할 Factor 검증 URL들의 Matcher

    public MfaStepFilterWrapper(FeatureRegistry featureRegistry,
                                ContextPersistence contextPersistence,
                                RequestMatcher mfaFactorProcessingMatcher) {
        this.featureRegistry = Objects.requireNonNull(featureRegistry);
        this.contextPersistence = Objects.requireNonNull(contextPersistence);
        this.mfaFactorProcessingMatcher = Objects.requireNonNull(mfaFactorProcessingMatcher, "mfaFactorProcessingMatcher cannot be null for MfaStepFilterWrapper");
        log.info("MfaStepFilterWrapper initialized. Will process requests matching: [configured matcher]");
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

        // FactorContext 유효성 검사 및 현재 처리 중인 Factor, 상태 확인
        if (ctx == null || ctx.getCurrentProcessingFactor() == null ||
                ctx.getCurrentState() != MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            log.warn("MfaStepFilterWrapper: Invalid attempt to process MFA factor. Context/State/Factor mismatch. URI: {}, State: {}, CurrentFactor: {}",
                    request.getRequestURI(),
                    (ctx != null ? ctx.getCurrentState() : "N/A"),
                    (ctx != null ? ctx.getCurrentProcessingFactor() : "N/A"));
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid MFA step or session.");
            return;
        }

        AuthType currentFactorType = ctx.getCurrentProcessingFactor();
        String factorId = currentFactorType.name().toLowerCase();

        // FeatureRegistry를 통해 해당 Factor를 처리하도록 "미리 설정된/등록된" 스프링 시큐리티 필터를 가져옴.
        // 이 필터는 PlatformSecurityConfig에서 MFA 플로우의 각 Factor (.ott(), .passkey())를 설정할 때
        // HttpSecurity에 추가된 해당 인증 방식의 표준 필터(예: AuthenticationFilter for OTT)여야 함.
        // FeatureRegistry.registerFactorFilter()를 통해 이 매핑이 이루어져야 함 (SecurityFilterChainRegistrar에서 담당).
        Filter delegateFactorFilter = featureRegistry.getFactorFilter(factorId);

        if (delegateFactorFilter != null) {
            log.info("MfaStepFilterWrapper: Delegating MFA step processing for factor '{}' to filter: {}. Session: {}",
                    factorId, delegateFactorFilter.getClass().getName(), ctx.getMfaSessionId());

            // 위임된 필터가 FactorContext에 접근해야 할 경우, 요청 속성으로 전달 가능 (선택적)
            // request.setAttribute(FactorContextManager.MFA_CONTEXT_SESSION_ATTRIBUTE_NAME, ctx); // 또는 mfaSessionId만 전달

            // 스프링 시큐리티 인증 필터는 요청을 처리하고 응답을 직접 커밋하거나,
            // 연결된 success/failure handler를 호출하여 응답을 위임함.
            // 따라서 이 wrapper는 chain.doFilter()를 호출하지 않음.
            delegateFactorFilter.doFilter(request, response, chain);
            // 여기서 return 하여 추가 필터 체인 진행을 막는 것이 일반적.
            return;
        } else {
            log.error("MfaStepFilterWrapper: No delegate filter found in FeatureRegistry for MFA factor: {}. This indicates a critical configuration error. Session: {}",
                    factorId, ctx.getMfaSessionId());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "MFA factor processing misconfiguration for " + factorId);
            return;
        }
    }
}

