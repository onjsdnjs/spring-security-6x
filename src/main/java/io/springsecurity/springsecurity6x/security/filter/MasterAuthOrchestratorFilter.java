package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.MfaFilterChainExecutor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * 모든 요청을 가로채어 ‘단일 인증’ vs ‘MFA 인증’을 근원적으로 분리합니다.
 */
public class MasterAuthOrchestratorFilter extends OncePerRequestFilter {
    private final Set<String> mfaEntryPoints;
    private final MfaFilterChainExecutor mfaExecutor;

    /**
     * @param mfaEntryPoints  예: "/api/auth/mfa", "/api/auth/mfa/step2" 등
     * @param mfaExecutor     MFA 전용 필터체인을 수행하는 실행기
     */
    public MasterAuthOrchestratorFilter(Set<String> mfaEntryPoints, MfaFilterChainExecutor mfaExecutor) {
        this.mfaEntryPoints = mfaEntryPoints;
        this.mfaExecutor    = mfaExecutor;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String path = req.getRequestURI();
        // 1) MFA URL 이면
        if (mfaEntryPoints.stream().anyMatch(path::startsWith)) {
            // → MFA 전용 체인 실행, 기본 SecurityFilterChain 은 건너뜀
            mfaExecutor.execute(req, res);
        }
        // 2) 그 외 일반 인증 요청이면
        else {
            // → 기본 Spring Security 체인(단일 인증)으로 넘어감
            chain.doFilter(req, res);
        }
    }
}

