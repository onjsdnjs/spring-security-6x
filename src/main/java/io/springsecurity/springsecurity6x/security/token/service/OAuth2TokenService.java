package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import org.springframework.security.core.Authentication;

public class OAuth2TokenService implements TokenService {

    private final TokenCreator tokenCreator;
    private final TokenValidator tokenValidator;

    public OAuth2TokenService(TokenCreator tokenCreator,
                              TokenParser tokenParser,
                              TokenValidator tokenValidator,
                              RefreshTokenStore refreshTokenStore) {
        this.tokenCreator = tokenCreator;
        this.tokenValidator = tokenValidator;
    }

    @Override
    public String createAccessToken(Authentication authentication) {
        return tokenCreator.createToken(null);
    }

    @Override
    public String createRefreshToken(Authentication authentication) {
        throw new UnsupportedOperationException("OAuth2 Client Credentials Flow에서는 refresh token을 발급하지 않습니다.");
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        throw new UnsupportedOperationException("OAuth2 Client Credentials Flow에서는 refresh token 갱신을 지원하지 않습니다.");
    }

    @Override
    public boolean validateAccessToken(String token) {
        return tokenValidator.validateAccessToken(token);
    }

    @Override
    public boolean validateRefreshToken(String token) {
        return tokenValidator.validateRefreshToken(token);
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {
        tokenValidator.invalidateRefreshToken(refreshToken);
    }

    @Override
    public Authentication getAuthentication(String token) {
        return tokenValidator.getAuthentication(token);
    }

    @Override
    public boolean shouldRotateRefreshToken(String refreshToken) {
        return false;
    }
}


