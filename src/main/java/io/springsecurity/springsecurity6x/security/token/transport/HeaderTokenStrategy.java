package io.springsecurity.springsecurity6x.security.token.transport;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static io.springsecurity.springsecurity6x.security.token.service.TokenService.*;

public class HeaderTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    private TokenService tokenService;

    public HeaderTokenStrategy(AuthContextProperties props) {
        super(props);
    }

    @Override
    public void setTokenService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        String authHeader = request.getHeader(ACCESS_TOKEN_HEADER);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return request.getHeader(REFRESH_TOKEN_HEADER);
    }

    @Override
    public void writeAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) {
        TokenResponse body = new TokenResponse(
                accessToken,
                "Bearer",
                tokenService.properties().getAccessTokenValidity(),
                refreshToken
        );
        writeJson(response, body);
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        writeJson(response, new TokenResponse(null, null, 0, null));
    }
}
