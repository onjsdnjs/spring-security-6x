package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public JwtAuthorizationFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest  request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token = null;
        String header = request.getHeader("Authorization");

        // 1) 헤더에 Bearer 토큰이 있으면 그것 사용
        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
        } else {
            // 2) 아니면 accessToken 쿠키에서 꺼내보기
            if (request.getCookies() != null) {
                for (Cookie c : request.getCookies()) {
                    if ("accessToken".equals(c.getName())) {
                        token = c.getValue();
                    }
                }
            }
        }

        // 3) 토큰이 있으면 검증
        if (token != null) {
            try {
                if (!tokenService.validateAccessToken(token)) {
                    response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired JWT token");
                    return;
                }
                Authentication auth = tokenService.getAuthenticationFromAccessToken(token);
                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception ex) {
                SecurityContextHolder.clearContext();
                response.sendError(HttpStatus.UNAUTHORIZED.value(), "Failed to authenticate JWT token");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}