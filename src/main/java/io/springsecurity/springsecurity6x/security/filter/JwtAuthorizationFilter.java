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
    protected void doFilterInternal(HttpServletRequest  request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1) Authorization 헤더 가져오기
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 2) 헤더가 있고 Bearer 토큰이라면 검증 로직 수행
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                // 2-1) 유효성 체크
                if (!tokenService.validateAccessToken(token)) {
                    response.sendError(
                            HttpStatus.UNAUTHORIZED.value(),
                            "Invalid or expired JWT token"
                    );
                    return;
                }
                // 2-2) 인증 정보 세팅
                Authentication auth = tokenService.getAuthenticationFromAccessToken(token);
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception ex) {
                // 토큰 처리 중 예외 발생 시 인증 컨텍스트 정리 후 401 리턴
                SecurityContextHolder.clearContext();
                response.sendError(
                        HttpStatus.UNAUTHORIZED.value(),
                        "Failed to authenticate JWT token"
                );
                return;
            }
        }

        // 3) 헤더가 없거나 Bearer 토큰이 아닌 요청은 그대로 통과
        filterChain.doFilter(request, response);
    }
}