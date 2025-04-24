package io.springsecurity.springsecurity6x.security.handler;

import io.springsecurity.springsecurity6x.security.token.service.JwtsTokenProvider;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.util.WebUtils;

public class TokenLogoutHandler implements LogoutHandler {
    private final TokenService tokenService;

    public TokenLogoutHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // 1) 리프레시 토큰 무효화
        Cookie refreshCookie = WebUtils.getCookie(request, TokenService.REFRESH_TOKEN);
        if (refreshCookie != null) {
            String refreshToken = refreshCookie.getValue();
            tokenService.invalidateToken(refreshToken);
        }

        // 2) accessToken, refreshToken 쿠키 만료 처리
        ResponseCookie expiredAccess = ResponseCookie.from(TokenService.ACCESS_TOKEN, "")
                .path("/")
                .httpOnly(true)
                .secure(request.isSecure())
                .sameSite("Strict")
                .maxAge(0)
                .build();

        ResponseCookie expiredRefresh = ResponseCookie.from(TokenService.REFRESH_TOKEN, "")
                .path("/")
                .httpOnly(true)
                .secure(request.isSecure())
                .sameSite("Strict")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, expiredAccess.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, expiredRefresh.toString());

        // 3) SecurityContext 클리어
        SecurityContextHolder.clearContext();
    }
}
