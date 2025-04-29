package io.springsecurity.springsecurity6x.security.handler.logout;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * JWT (Internal) 기반 TokenLogoutHandler
 * - RefreshToken 무효화
 * - AccessToken, RefreshToken 쿠키/헤더 삭제
 * - SecurityContext 초기화
 */
public class TokenLogoutHandler implements LogoutHandler {

    private final TokenService tokenService;
    private final TokenTransportStrategy transport;

    public TokenLogoutHandler(TokenService tokenService, TokenTransportStrategy transport) {
        this.tokenService = tokenService;
        this.transport = transport;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refreshToken = transport.resolveRefreshToken(request);
        if (refreshToken != null) {
            tokenService.invalidateRefreshToken(refreshToken);
        }
        transport.clearTokens(response);
        SecurityContextHolder.clearContext();
    }
}

