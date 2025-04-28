package io.springsecurity.springsecurity6x.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ResourceClient;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Map;

/**
 * OAuth2 기반 인증 성공/실패 핸들러 구현체
 * - accessToken을 발급받아 Header 또는 Cookie 방식으로 전송
 */
public class OAuth2AuthenticationHandlers implements AuthenticationHandlers {

    private final OAuth2ResourceClient resourceClient;
    private final TokenTransportStrategy transport;

    public OAuth2AuthenticationHandlers(OAuth2ResourceClient resourceClient, TokenTransportStrategy transport) {
        this.resourceClient = resourceClient;
        this.transport = transport;
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            // 인가 서버로부터 AccessToken 발급
            String accessToken = resourceClient.issueAccessToken(authentication.getName());

            // AccessToken을 Header 또는 Cookie 방식으로 전송
            transport.writeAccessToken(response, accessToken);

            // JSON 성공 응답
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
            new ObjectMapper().writeValue(
                    response.getWriter(),
                    Map.of("message", "Authentication Successful (OAuth2)")
            );
        };
    }

    @Override
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "OAuth2 Authentication Failed");
    }
}
