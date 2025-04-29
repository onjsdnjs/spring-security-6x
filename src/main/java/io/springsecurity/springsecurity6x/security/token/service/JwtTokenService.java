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

public class JwtTokenService implements TokenService {

    private final TokenValidator tokenValidator;
    private final TokenCreator tokenCreator;
    private final RefreshTokenStore tokenStore;
    private final AuthContextProperties properties;


    public JwtTokenService(TokenValidator tokenValidator, TokenCreator tokenCreator,
                           RefreshTokenStore tokenStore, AuthContextProperties properties) {
        this.tokenValidator     = tokenValidator;
        this.tokenCreator       = tokenCreator;
        this.tokenStore = tokenStore;
        this.properties         = properties;
    }

    @Override
    public String createAccessToken(Authentication authentication) {

        TokenRequest tokenRequest = TokenRequest.builder()
                .tokenType("access")
                .username(authentication.getName())
                .roles(getRoles(authentication))
                .validity(properties.getInternal().getAccessTokenValidity())
                .build();

        return tokenCreator.createToken(tokenRequest);

    }

    @Override
    public String createRefreshToken(Authentication authentication) {

        TokenRequest tokenRequest = TokenRequest.builder()
                .tokenType("refresh")
                .username(authentication.getName())
                .roles(getRoles(authentication))
                .validity(properties.getInternal().getRefreshTokenValidity())
                .build();

        String token = tokenCreator.createToken(tokenRequest);
        tokenStore.store(token, authentication.getName());
        return token;
    }

    @Override
    public RefreshResult refresh(String refreshToken) {

        if (!validateRefreshToken(refreshToken)) throw new TokenValidationException("Invalid refresh token");

        Authentication auth = getAuthentication(refreshToken);
        String newAccess = createAccessToken(auth);
        String newRefresh = refreshToken;

        boolean rotateEnabled = properties.getInternal().isEnableRefreshToken();
        if (rotateEnabled && tokenValidator.shouldRotateRefreshToken(refreshToken)) {
            tokenStore.remove(refreshToken);
            newRefresh = createRefreshToken(auth);
            tokenStore.store(newRefresh, auth.getName());
        }
        return new RefreshResult(newAccess, newRefresh);
    }

    @Override
    public boolean validateAccessToken(String accessToken) {
        return accessToken != null && tokenValidator.validateAccessToken(accessToken);
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
    public void invalidateRefreshToken(String token) {
        tokenValidator.invalidateRefreshToken(token);
    }

    private List<String> getRoles(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}

