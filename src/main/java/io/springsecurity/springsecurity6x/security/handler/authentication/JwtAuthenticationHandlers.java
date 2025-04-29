package io.springsecurity.springsecurity6x.security.handler.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.handler.logout.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.Map;

/**
 * JWT 기반 인증 성공/실패 핸들러 구현체.
 * – accessToken / refreshToken 을 생성·전송한다.
 */
public class JwtAuthenticationHandlers implements AuthenticationHandlers {

    private final TokenService tokenService;
    private final TokenTransportStrategy transport;
    private final AuthContextProperties properties;

    public JwtAuthenticationHandlers(TokenService tokenService,
                                     TokenTransportStrategy transport,
                                     AuthContextProperties properties) {
        this.tokenService = tokenService;
        this.transport = transport;
        this.properties = properties;
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {

        return (request, response, authentication) -> {
            String accessToken = tokenService.createAccessToken(authentication);
            String refreshToken = null;
            if (properties.getInternal().isEnableRefreshToken()) {
                refreshToken = tokenService.createRefreshToken(authentication);
            }
            // Header 또는 Cookie 방식으로 전송
            transport.writeAccessToken(response, accessToken);
            if (refreshToken != null) {
                transport.writeRefreshToken(response, refreshToken);
            }

            // JSON 응답 (message)
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
        return new TokenLogoutHandler(tokenService, transport);
    }
}

