package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 1) Authorization 헤더가 없거나 Bearer 토큰이 아닐 경우 차단
        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Authorization header is missing or invalid");
            return;
        }

        String token = header.substring(7);

        try {
            // 2) 토큰 유효성 검증
            if (!tokenService.validateAccessToken(token)) {
                response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired JWT token");
                return;
            }

            // 3) 인증 정보 세팅
            Authentication authentication = tokenService.getAuthenticationFromAccessToken(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 4) 다음 필터로 진행
            filterChain.doFilter(request, response);

        } catch (Exception ex) {
            // 토큰 처리 중 예외 발생 시 SecurityContext 정리 후 401
            SecurityContextHolder.clearContext();
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Failed to authenticate JWT token");
        }
    }
}