package io.springsecurity.springsecurity6x.security.handler.logout;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * OAuth2 기반 LogoutHandler
 * - AccessToken만 삭제
 * - SecurityContext 초기화는 필터(OAuth2AuthorizationFilter)에서 별도로 수행
 */
public class OAuth2LogoutHandler implements LogoutHandler {

    private final TokenService tokenService;

    public OAuth2LogoutHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//        tokenService.clearTokens(response);
        SecurityContextHolder.clearContext();
    }
}


