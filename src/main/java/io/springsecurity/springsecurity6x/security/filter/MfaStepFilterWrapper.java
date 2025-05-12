package io.springsecurity.springsecurity6x.security.filter;
import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * 현재 MFA 단계에 대응하는 실제 AuthenticationFilter를 꺼내 호출합니다.
 * - MfaOrchestrationFilter 에서 req.setAttribute("currentFactor", factorId) 해 두면,
 *   이 클래스가 그 attribute를 읽어 알맞은 필터를 실행합니다.
 */
public class MfaStepFilterWrapper implements Filter {
    private static final String ATTR_FACTOR = "currentFactor";

    private final FeatureRegistry featureRegistry;
    private final ContextPersistence ctxPersistence;

    public MfaStepFilterWrapper(FeatureRegistry featureRegistry, ContextPersistence ctxPersistence) {
        this.featureRegistry = featureRegistry;
        this.ctxPersistence  = ctxPersistence;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest)  request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 현재 단계(factorId)를 RequestAttribute 에서 가져옵니다.
        String factor = (String) req.getAttribute(ATTR_FACTOR);
        if (factor != null) {
            // FeatureRegistry에 등록된 필터를 꺼냅니다.
            Filter delegate = featureRegistry.getFactorFilter(factor);
            if (delegate != null) {
                // 실제 Spring 인증 필터를 실행
                delegate.doFilter(req, res, chain);
                return;
            }
        }

        // factor가 없거나 매칭되는 필터가 없으면 다음 필터로
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // 리소스 해제 불필요
    }
}

