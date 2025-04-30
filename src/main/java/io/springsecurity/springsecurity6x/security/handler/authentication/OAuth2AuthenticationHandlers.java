package io.springsecurity.springsecurity6x.security.handler.authentication;

import io.springsecurity.springsecurity6x.security.handler.logout.OAuth2LogoutHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;

/**
 * OAuth2 기반 인증 성공/실패 핸들러 구현체
 * - TokenService를 사용하여 accessToken 발급 및 전송
 */
public class OAuth2AuthenticationHandlers implements AuthenticationHandlers {

    private final TokenService tokenService;

    public OAuth2AuthenticationHandlers(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {

            String deviceId = request.getHeader("X-Device-Id"); // deviceId 추출
            if (!StringUtils.hasText(deviceId)) {
                throw new BadCredentialsException("Device ID is missing");
            }

            String accessToken = tokenService.createAccessToken(authentication, deviceId);
            tokenService.writeAccessAndRefreshToken(response, accessToken, null);
        };
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed");
    }

    public LogoutHandler logoutHandler(){
        return new OAuth2LogoutHandler(tokenService);
    }
}

