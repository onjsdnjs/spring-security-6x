package io.springsecurity.springsecurity6x.security.token.service;

import org.springframework.security.core.Authentication;

public interface TokenProvider {
    String createAccessToken(Authentication authentication, String deviceId);
    String createRefreshToken(Authentication authentication, String deviceId);
    TokenService.RefreshResult refresh(String refreshToken);
}
