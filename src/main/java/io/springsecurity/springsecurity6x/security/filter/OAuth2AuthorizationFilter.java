package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * OAuth2 Authorization Server 기반 토큰 검증 필터
 * TokenService를 통해 access token 검증 및 자동 재발급 지원
 */
public class OAuth2AuthorizationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final LogoutHandler logoutHandler;

    public OAuth2AuthorizationFilter(TokenService tokenService, LogoutHandler logoutHandler) {
        this.tokenService = tokenService;
        this.logoutHandler = logoutHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String accessToken = tokenService.resolveAccessToken(request);

        if (accessToken != null) {
            try {
                if (tokenService.validateAccessToken(accessToken)) {
                    Authentication authentication = tokenService.getAuthentication(accessToken);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                SecurityContextHolder.clearContext();
                logoutHandler.logout(request, response, null);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid access token");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
