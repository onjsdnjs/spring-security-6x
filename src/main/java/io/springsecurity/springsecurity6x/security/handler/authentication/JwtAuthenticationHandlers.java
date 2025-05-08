package io.springsecurity.springsecurity6x.security.handler.authentication;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;

/**
 * JWT 기반 인증 성공/실패 핸들러 구현체.
 * – accessToken / refreshToken 을 생성·전송한다.
 */
@Slf4j
public class JwtAuthenticationHandlers implements AuthenticationHandlers {

    private final TokenService tokenService;

    public JwtAuthenticationHandlers(TokenService tokenService) {
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
            String refreshToken = tokenService.createRefreshToken(authentication, deviceId);
            try {
                tokenService.writeAccessAndRefreshToken(response, accessToken, refreshToken);
            } catch (Exception e) {
                log.error("Token creation or response writing failed", e);
                throw new AuthenticationServiceException("토큰 발급 실패", e);
            }
        };
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT Authentication Failed");
    }

   /* public LogoutHandler logoutHandler(){
        return new JwtLogoutHandler(tokenService);
    }*/
}

