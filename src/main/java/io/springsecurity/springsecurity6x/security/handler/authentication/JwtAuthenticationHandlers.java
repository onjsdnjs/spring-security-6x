package io.springsecurity.springsecurity6x.security.handler.authentication;

import io.springsecurity.springsecurity6x.security.handler.logout.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * JWT 기반 인증 성공/실패 핸들러 구현체.
 * – accessToken / refreshToken 을 생성·전송한다.
 */
public class JwtAuthenticationHandlers implements AuthenticationHandlers {

    private final TokenService tokenService;

    public JwtAuthenticationHandlers(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            String accessToken = tokenService.createAccessToken(authentication);
            String refreshToken = tokenService.createRefreshToken(authentication);
            tokenService.writeAccessAndRefreshToken(response, accessToken, refreshToken);
        };
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT Authentication Failed");
    }

    public LogoutHandler logoutHandler(){
        return new TokenLogoutHandler(tokenService);
    }
}

