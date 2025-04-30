package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

public class OAuth2TokenService implements TokenService {

    private final TokenCreator tokenCreator;
    private final TokenValidator tokenValidator;
    private final TokenTransportStrategy transport;
    private final AuthContextProperties props;

    public OAuth2TokenService(TokenCreator tokenCreator, TokenValidator tokenValidator, TokenTransportStrategy transport, AuthContextProperties props) {
        this.tokenCreator = tokenCreator;
        this.tokenValidator = tokenValidator;
        this.transport = transport;
        this.props = props;
    }

    @Override
    public String createAccessToken(Authentication authentication) {
        return tokenCreator.createToken(null);
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return transport.resolveRefreshToken(request);
    }


    @Override
    public void writeAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken){
        transport.writeAccessAndRefreshToken(response, accessToken, refreshToken);
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
        return false; // Client Credentials Flow에서는 refresh_token 사용 안함
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {
        throw new UnsupportedOperationException("OAuth2 Client Credentials Flow에서는 refresh token 무효화를 지원하지 않습니다.");
    }

    @Override
    public Authentication getAuthentication(String token) {
        return tokenValidator.getAuthentication(token);
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        return transport.resolveAccessToken(request);
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        transport.clearTokens(response);
    }

    @Override
    public AuthContextProperties properties() {
        return props;
    }

    @Override
    public void blacklist(String refreshToken, String username) {

    }
}




