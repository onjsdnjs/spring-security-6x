package io.springsecurity.springsecurity6x.security.token.service;

import org.springframework.security.core.Authentication;

public interface TokenProvider {
    String createAccessToken(Authentication authentication);
    String createRefreshToken(Authentication authentication);
    TokenService.RefreshResult refresh(String refreshToken);
}
