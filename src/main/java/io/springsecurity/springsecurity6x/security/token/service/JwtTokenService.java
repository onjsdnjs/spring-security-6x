package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.exception.TokenValidationException;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenRequest;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.stream.Collectors;

public class JwtTokenService implements TokenService {

    private final TokenCreator tokenCreator;
    private final TokenValidator tokenValidator;
    private final RefreshTokenStore tokenStore;
    private final TokenTransportStrategy transport;
    private final AuthContextProperties props;

    public JwtTokenService(TokenValidator tokenValidator, TokenCreator tokenCreator, RefreshTokenStore tokenStore,
                           TokenTransportStrategy transport, AuthContextProperties props) {
        this.tokenCreator = tokenCreator;
        this.tokenValidator = tokenValidator;
        this.tokenStore = tokenStore;
        this.transport = transport;
        this.props = props;
    }

    @Override
    public String createAccessToken(Authentication authentication) {
        TokenRequest tokenRequest = TokenRequest.builder()
                .tokenType("access")
                .username(authentication.getName())
                .roles(authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .validity(props.getAccessTokenValidity())
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
                        .collect(Collectors.toList()))
                .validity(props.getRefreshTokenValidity())
                .build();

        String token = tokenCreator.createToken(tokenRequest);
        tokenStore.store(token, authentication.getName());
        return token;
    }

    @Override
    public RefreshResult refresh(String refreshToken) {

        if (!validateRefreshToken(refreshToken)) {
            throw new TokenValidationException("Invalid refresh token");
        }

        Authentication auth = getAuthentication(refreshToken);
        String newAccessToken = createAccessToken(auth);
        String newRefreshToken = refreshToken;

        boolean rotateEnabled = props.isEnableRefreshToken();
        if (rotateEnabled && tokenValidator.shouldRotateRefreshToken(refreshToken)) {
            tokenStore.remove(refreshToken);
            newRefreshToken = createRefreshToken(auth);
            tokenStore.store(newRefreshToken, auth.getName());
        }
        return new RefreshResult(newAccessToken, newRefreshToken);
    }

    @Override
    public void writeAccessToken(HttpServletResponse response, String accessToken) {
        transport.writeAccessToken(response, accessToken);
    }

    @Override
    public void writeRefreshToken(HttpServletResponse response, String refreshToken) {
        transport.writeRefreshToken(response, refreshToken);
    }

    @Override
    public void writeAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken){
        transport.writeAccessAndRefreshToken(response, accessToken, refreshToken);
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
        tokenStore.remove(refreshToken);
    }

    @Override
    public Authentication getAuthentication(String token) {
        return  tokenValidator.getAuthentication(token);
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        return transport.resolveAccessToken(request);
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return transport.resolveRefreshToken(request);
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        transport.clearTokens(response);
    }

    @Override
    public AuthContextProperties properties() {
        return props;
    }
}


