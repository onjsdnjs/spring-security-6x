package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final TokenTransportStrategy transport;
    private final LogoutHandler logoutHandler;

    public JwtAuthorizationFilter(TokenService tokenService, TokenTransportStrategy transport, LogoutHandler logoutHandler) {
        this.tokenService = tokenService;
        this.transport = transport;
        this.logoutHandler = logoutHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String accessToken = transport.resolveAccessToken(request);

        if (accessToken != null) {
            try {
                if (tokenService.validateAccessToken(accessToken)) {
                    Authentication authentication = tokenService.getAuthentication(accessToken);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                // 토큰 검증 실패 시 전체 인증정보 클리어 + 로그아웃
                logoutHandler.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid access token");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}


