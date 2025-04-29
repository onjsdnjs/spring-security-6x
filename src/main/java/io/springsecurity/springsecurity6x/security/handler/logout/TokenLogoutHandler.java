package io.springsecurity.springsecurity6x.security.handler.logout;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
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

    public TokenLogoutHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refreshToken = tokenService.resolveRefreshToken(request);
        if (refreshToken != null) {
            tokenService.invalidateRefreshToken(refreshToken);
        }
        tokenService.clearTokens(response);
        SecurityContextHolder.clearContext();
    }
}

