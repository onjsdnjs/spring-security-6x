package io.springsecurity.springsecurity6x.security.handler.logout;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.TokenInfo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * JWT (Internal) 기반 TokenLogoutHandler
 * - RefreshToken 무효화
 * - AccessToken, RefreshToken 쿠키/헤더 삭제
 * - SecurityContext 초기화
 */
public class JwtLogoutHandler implements LogoutHandler {

    private final TokenService tokenService;

    public JwtLogoutHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refreshToken = tokenService.resolveRefreshToken(request);

        try {
            if (refreshToken != null && authentication != null) {
                tokenService.invalidateRefreshToken(refreshToken); // ← 내부에서 AuthenticationException 던질 수 있음
                tokenService.blacklistRefreshToken(refreshToken, authentication.getName(), TokenInfo.REASON_LOGOUT);
            }
        } catch (AuthenticationException ex) {
            SecurityContextHolder.clearContext(); // 무조건 context는 비우고
            throw ex; // 예외 전파 (→ EntryPoint로)
        }

        tokenService.clearTokens(response);
        SecurityContextHolder.clearContext();
    }
}

