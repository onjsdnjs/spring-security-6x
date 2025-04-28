package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.exception.TokenValidationException;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenRequest;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public class InternalJwtTokenService implements TokenService {

    private final TokenValidator tokenValidator;
    private final TokenCreator tokenCreator;
    private final RefreshTokenStore refreshTokenStore;
    private final AuthContextProperties properties;


    public InternalJwtTokenService(TokenValidator tokenValidator, TokenCreator tokenCreator,
                                   RefreshTokenStore refreshTokenStore, AuthContextProperties properties) {
        this.tokenValidator     = tokenValidator;
        this.tokenCreator       = tokenCreator;
        this.refreshTokenStore  = refreshTokenStore;
        this.properties         = properties;
    }

    @Override
    public boolean validateRefreshToken(String refreshToken) {
        return refreshToken != null && tokenValidator.validateRefreshToken(refreshToken);
    }

    @Override
    public Authentication getAuthentication(String refreshToken) {
        return tokenValidator.getAuthentication(refreshToken);
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        if (!validateRefreshToken(refreshToken)) {
            throw new TokenValidationException("Invalid refresh token");
        }

        Authentication auth = getAuthentication(refreshToken);
        String newAccess = createAccessToken(auth);
        String newRefresh = refreshToken;

        boolean rotateEnabled = properties.getInternal().isEnableRefreshToken();
        if (rotateEnabled && tokenValidator.shouldRotateRefreshToken(refreshToken)) {
            refreshTokenStore.remove(refreshToken);
            newRefresh = createRefreshToken(auth);
            refreshTokenStore.store(newRefresh, auth.getName());
        }

        return new RefreshResult(newAccess, newRefresh);
    }

    @Override
    public String createAccessToken(Authentication authentication) {

        TokenRequest tokenRequest = TokenRequest.builder()
                .tokenType("access")
                .username(authentication.getName())
                .roles(authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .validity(properties.getInternal().getAccessTokenValidity())
                .build();

        return tokenCreator.createToken(tokenRequest);

    }

    @Override
    public String createRefreshToken(Authentication authentication) {

        TokenRequest tokenRequest = TokenRequest.builder()
                .tokenType("refresh")
                .username(authentication.getName())
                .roles(authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .validity(properties.getInternal().getRefreshTokenValidity())
                .build();

        return tokenCreator.createToken(tokenRequest);
    }

    private List<String> getRoles(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}

