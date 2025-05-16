package io.springsecurity.springsecurity6x.security.token.transport;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.StringUtils;

import java.util.Map;

import static io.springsecurity.springsecurity6x.security.token.service.TokenService.ACCESS_TOKEN;
import static io.springsecurity.springsecurity6x.security.token.service.TokenService.REFRESH_TOKEN;

public class CookieTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    private static final String COOKIE_PATH = "/";
    private TokenService tokenService;

    protected CookieTokenStrategy(AuthContextProperties props) {
        super(props);
    }

/*    @Override
    public void setTokenService(TokenService tokenService) {
        this.tokenService = tokenService;
    }*/

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        return extractCookie(request, ACCESS_TOKEN);
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return extractCookie(request, REFRESH_TOKEN);
    }

    @Override
    public TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken, TokenService.TokenServicePropertiesProvider tokenServiceProperties) {
        return null;
    }

    @Override
    public TokenTransportResult prepareTokensForClear(TokenService.TokenServicePropertiesProvider tokenServiceProperties) {
        return null;
    }

/*    @Override
    public void writeAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) {
        if (StringUtils.hasText(accessToken)) {
            addCookie(response, ACCESS_TOKEN, accessToken,
                    (int) tokenService.properties().getAccessTokenValidity() / 1000, COOKIE_PATH);
        }
        if (StringUtils.hasText(refreshToken)) {
            addCookie(response, REFRESH_TOKEN, refreshToken,
                    (int) tokenService.properties().getRefreshTokenValidity() / 1000, COOKIE_PATH);
        }
        writeJson(response, Map.of("message", "Authentication Successful (JWT)"));
    }*/

/*    @Override
    public void clearTokens(HttpServletResponse response) {
        removeCookie(response, ACCESS_TOKEN, COOKIE_PATH);
        removeCookie(response, REFRESH_TOKEN, COOKIE_PATH);
    }*/
}



