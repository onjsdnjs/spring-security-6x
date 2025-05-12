package io.springsecurity.springsecurity6x.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * MFA 진입점이 되는 Filter.
 *  - "/api/auth/mfa" 같은 단일 엔드포인트만 매칭
 *  - 내부적으로 각 Flow별 SecurityFilterChain 을 꺼내 인증용 Filter만 순차 doFilter() 호출
 */
public class MfaAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain)
            throws ServletException, IOException {
    }
}

