package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);
    void writeAccessToken(HttpServletResponse response, String accessToken);
    void writeRefreshToken(HttpServletResponse response, String refreshToken);
    void writeAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) throws Exception;
    void clearTokens(HttpServletResponse response);
    AuthContextProperties properties();
    record RefreshResult(String accessToken, String refreshToken) {}
}


