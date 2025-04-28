package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ResourceClient;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2TokenProvider;
import org.springframework.security.core.Authentication;

public class ExternalTokenService implements TokenService {

    private final OAuth2TokenProvider tokenProvider;
    private final OAuth2ResourceClient resourceClient;

    public ExternalTokenService(OAuth2TokenProvider tokenProvider, OAuth2ResourceClient resourceClient) {
        this.tokenProvider = tokenProvider;
        this.resourceClient = resourceClient;
    }

    @Override
    public String createAccessToken(Authentication authentication) {
        return tokenProvider.getAccessToken();
    }

    @Override
    public String createRefreshToken(Authentication authentication) {
        return "";
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        return null;
    }

    @Override
    public boolean validateAccessToken(String accessToken) {
        return resourceClient.validateAccessToken(accessToken);
    }

    @Override
    public boolean validateRefreshToken(String token) {
        return false;
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {

    }

    @Override
    public Authentication getAuthentication(String accessToken) {
        throw new UnsupportedOperationException("OAuth2 인증 흐름에서는 Authentication 객체를 생성하지 않습니다.");
    }
}

