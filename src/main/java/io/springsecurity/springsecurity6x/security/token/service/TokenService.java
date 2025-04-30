package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;

public interface TokenService extends TokenProvider, TokenValidator, TokenTransportStrategy {

    String ACCESS_TOKEN = "accessToken";
    String REFRESH_TOKEN = "refreshToken";
    String ACCESS_TOKEN_HEADER  = "Authorization";
    String REFRESH_TOKEN_HEADER = "X-Refresh-Token";
    String BEARER_PREFIX        = "Bearer ";

    AuthContextProperties properties();
    void blacklist(String refreshToken, String username);
    record RefreshResult(String accessToken, String refreshToken) {}
}


