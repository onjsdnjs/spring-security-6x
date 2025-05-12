package io.springsecurity.springsecurity6x.security.core.mfa;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

/**
 * MFA 전용 필터 순서를 구성하여, MasterAuthOrchestratorFilter 에서 호출됩니다.
 */
public class MfaFilterChainExecutor {
    private final List<Filter> mfaFilters;

    public MfaFilterChainExecutor(List<Filter> mfaFilters) {
        this.mfaFilters = mfaFilters;
    }

    /**
     * 순서대로 필터를 실행, 마지막에는 응답 반환.
     * @see #mfaFilters 순서: MfaOrchestrationFilter → StepTransitionFilter → MfaStepFilterWrapper
     */
    public void execute(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        new VirtualFilterChain(mfaFilters).doFilter(req, res);
    }

    private static class VirtualFilterChain implements FilterChain {
        private final List<Filter> filters;
        private int index = 0;

        VirtualFilterChain(List<Filter> filters) {
            this.filters = filters;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response)
                throws IOException, ServletException {
            if (index == filters.size()) {
                // 체인 끝. 여기서 더 이상 기본 체인으로 넘어가지 않습니다.
                return;
            }
            Filter next = filters.get(index++);
            next.doFilter(request, response, this);
        }
    }
}

