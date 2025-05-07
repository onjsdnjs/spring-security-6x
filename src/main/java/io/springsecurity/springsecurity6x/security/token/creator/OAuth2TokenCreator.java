package io.springsecurity.springsecurity6x.security.token.creator;

import io.springsecurity.springsecurity6x.security.core.feature.state.oauth2.client.OAuth2TokenProvider;

public class OAuth2TokenCreator implements TokenCreator {

    private final OAuth2TokenProvider tokenProvider;

    public OAuth2TokenCreator(OAuth2TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public String createToken(TokenRequest request) {
        return tokenProvider.getAccessToken();
    }
}

