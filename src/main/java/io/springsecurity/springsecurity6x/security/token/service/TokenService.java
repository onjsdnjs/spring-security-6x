package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import org.springframework.security.core.Authentication;

public interface TokenService extends TokenValidator {

    String ACCESS_TOKEN = "accessToken";
    String REFRESH_TOKEN = "refreshToken";
    String ACCESS_TOKEN_HEADER  = "Authorization";
    String REFRESH_TOKEN_HEADER = "X-Refresh-Token";
    String BEARER_PREFIX        = "Bearer ";

    String createAccessToken(Authentication authentication);

    String createRefreshToken(Authentication authentication);

    RefreshResult refresh(String refreshToken);

    record RefreshResult(String accessToken, String refreshToken) {}

}

