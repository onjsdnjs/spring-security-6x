package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public class InternalJwtTokenService implements TokenService {

    private final TokenCreator tokenCreator;
    private final AuthContextProperties properties;

    public InternalJwtTokenService(TokenCreator tokenCreator, AuthContextProperties properties) {
        this.tokenCreator = tokenCreator;
        this.properties = properties;
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

