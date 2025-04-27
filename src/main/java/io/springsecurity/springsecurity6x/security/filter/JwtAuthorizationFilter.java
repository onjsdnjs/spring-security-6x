package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
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

    private final TokenValidator tokenValidator;
    private final TokenTransportHandler transportHandler;
    private final LogoutHandler logoutHandler;

    public JwtAuthorizationFilter(TokenValidator tokenValidator, TokenTransportHandler transportHandler, LogoutHandler logoutHandler) {
        this.tokenValidator = tokenValidator;
        this.transportHandler = transportHandler;
        this.logoutHandler = logoutHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String accessToken = transportHandler.extractAccessToken(request);

        if (accessToken != null) {
            try {
                if (tokenValidator.validateAccessToken(accessToken)) {
                    Authentication authentication = tokenValidator.getAuthentication(accessToken);
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


