package io.springsecurity.springsecurity6x.security.token.transport;

import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.StringUtils;

import static io.springsecurity.springsecurity6x.security.token.service.TokenService.*;

public class HeaderCookieTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    private static final String COOKIE_PATH = "/api/token/refresh";
    private TokenService tokenService;

    @Override
    public void setTokenService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        String header = request.getHeader(ACCESS_TOKEN_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return extractCookie(request, REFRESH_TOKEN);
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

        if (StringUtils.hasText(refreshToken)) {
            addCookie(response, REFRESH_TOKEN, refreshToken,
                    (int) tokenService.properties().getRefreshTokenValidity() / 1000, COOKIE_PATH);
        }
    }

    @Override
    public void clearTokens(HttpServletResponse response) {
        removeCookie(response, REFRESH_TOKEN, COOKIE_PATH);
    }
}

