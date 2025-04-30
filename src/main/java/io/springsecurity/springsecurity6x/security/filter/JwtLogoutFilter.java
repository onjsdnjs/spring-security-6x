package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtLogoutFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public JwtLogoutFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // 로그아웃 URI일 때만 access 토큰으로 인증 처리
        if ("/api/auth/logout".equals(request.getRequestURI())) {
            String token = tokenService.resolveAccessToken(request);
            if (StringUtils.hasText(token) && tokenService.validateAccessToken(token)) {
                Authentication authentication = tokenService.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }
}
