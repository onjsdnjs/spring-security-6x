package io.springsecurity.springsecurity6x.security.filter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorContext;
import io.springsecurity.springsecurity6x.security.enums.MfaState;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 현재 MFA 단계에 대응하는 실제 AuthenticationFilter를 꺼내 호출합니다.
 * - MfaOrchestrationFilter 에서 req.setAttribute("currentFactor", factorId) 해 두면,
 *   이 클래스가 그 attribute를 읽어 알맞은 필터를 실행합니다.
 */
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private static final String ATTR_FACTOR = "currentFactor";

    private final FeatureRegistry featureRegistry;
    private final ContextPersistence ctxPersistence;
    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/auth/mfa/**");

    public MfaStepFilterWrapper(FeatureRegistry featureRegistry, ContextPersistence ctxPersistence) {
        this.featureRegistry = featureRegistry;
        this.ctxPersistence  = ctxPersistence;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (!requestMatcher.matches(req)) {
            chain.doFilter(req, res);
            return;
        }

        FactorContext ctx = ctxPersistence.loadOrInit(req);
        MfaState currentState = ctx.currentState();

        // TOKEN_ISSUANCE 또는 COMPLETED 상태에서는 인증 필터 실행 생략
        if (currentState == MfaState.TOKEN_ISSUANCE || currentState == MfaState.COMPLETED) {
            chain.doFilter(req, res);
            return;
        }

        // 현재 상태명에서 factorId 추출: 예) REST_CHALLENGE → rest
        String factorId = extractFactorId(currentState.name());
        if (factorId != null) {
            Filter delegate = featureRegistry.getFactorFilter(factorId);
            if (delegate != null) {
                req.setAttribute(ATTR_FACTOR, factorId);
                delegate.doFilter(req, res, chain);
                return;
            }
        }

        chain.doFilter(req, res);
    }

    private String extractFactorId(String stateName) {
        int underscoreIndex = stateName.indexOf('_');
        if (underscoreIndex > 0) {
            return stateName.substring(0, underscoreIndex).toLowerCase(); // "REST_CHALLENGE" → "rest"
        }
        return null;
    }
}


