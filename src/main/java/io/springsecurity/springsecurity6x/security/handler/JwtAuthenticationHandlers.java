package io.springsecurity.springsecurity6x.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenRequest;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportHandler;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.List;
import java.util.Map;

/**
 * JWT 기반 인증 성공/실패 핸들러 구현체.
 * – accessToken / refreshToken 을 생성·전송한다.
 */
public class JwtAuthenticationHandlers implements AuthenticationHandlers {

    private final TokenCreator tokenCreator;
    private final TokenTransportHandler transportHandler;
    private final AuthContextProperties properties;

    public JwtAuthenticationHandlers(TokenCreator tokenCreator,
                                     TokenTransportHandler transportHandler,
                                     AuthContextProperties properties) {
        this.tokenCreator = tokenCreator;
        this.transportHandler = transportHandler;
        this.properties = properties;
    }

    @Override
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            String username = authentication.getName();
            List<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            TokenRequest tokenRequest = TokenRequest.builder()
                    .tokenType("access")
                    .username(username)
                    .roles(authentication.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .toList())
                    .validity(properties.getInternal().getAccessTokenValidity())
                    .build();
            String accessToken = tokenCreator.createToken(tokenRequest);

            String refreshToken = null;
            if (properties.getInternal().isEnableRefreshToken()) {
                tokenRequest = TokenRequest.builder()
                        .tokenType("refresh")
                        .username(username)
                        .roles(authentication.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList())
                        .validity(properties.getInternal().getRefreshTokenValidity())
                        .build();

                refreshToken = tokenCreator.createToken(tokenRequest);
            }

            // Header 또는 Cookie 방식으로 전송
            transportHandler.sendAccessToken(response, accessToken);
            if (refreshToken != null) {
                transportHandler.sendRefreshToken(response, refreshToken);
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
}

