package io.springsecurity.springsecurity6x.security.handler.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.handler.logout.OAuth2LogoutHandler;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.Map;

/**
 * OAuth2 기반 인증 성공/실패 핸들러 구현체
 * - TokenService를 사용하여 accessToken 발급 및 전송
 */
public class OAuth2AuthenticationHandlers implements AuthenticationHandlers {

    private final TokenService tokenService;
    private final TokenTransportStrategy transport;

    public OAuth2AuthenticationHandlers(TokenService tokenService, TokenTransportStrategy transport) {
        this.tokenService = tokenService;
        this.transport = transport;
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            // accessToken 발급 (수동/자동 모두 TokenService가 처리)
            String accessToken = tokenService.createAccessToken(authentication);

            // AccessToken을 Header 또는 Cookie 방식으로 전송
            transport.writeAccessToken(response, accessToken);

            // JSON 성공 응답
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            new ObjectMapper().writeValue(
                    response.getWriter(),
                    Map.of("message", "Authentication Successful")
            );
        };
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed");
    }

    public LogoutHandler logoutHandler(){
        return new OAuth2LogoutHandler(transport);
    }
}

