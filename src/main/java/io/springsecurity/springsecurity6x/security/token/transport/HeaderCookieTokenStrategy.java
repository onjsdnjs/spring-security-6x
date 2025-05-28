package io.springsecurity.springsecurity6x.security.token.transport;

import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.springsecurity.springsecurity6x.security.token.service.TokenService.*;

public class HeaderCookieTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    private static final String COOKIE_PATH = "/";
    public HeaderCookieTokenStrategy(AuthContextProperties props) {
        super(props);
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
        return extractCookie(request, REFRESH_TOKEN); // AbstractTokenTransportStrategy의 메서드 사용
    }

    @Override
    public TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken, TokenService.TokenServicePropertiesProvider propsProvider) {
        Map<String, Object> body = new HashMap<>();
        body.put("accessToken", accessToken);
        body.put("tokenType", "Bearer");
        body.put("expiresIn", propsProvider.getAccessTokenValidity());
        body.put("tokenTransportMethod", "HEADER_COOKIE");

        List<ResponseCookie> cookiesToSet = new ArrayList<>();
        if (StringUtils.hasText(refreshToken)) {
            ResponseCookie refreshCookie = ResponseCookie.from(propsProvider.getRefreshTokenCookieName(), refreshToken)
                    .path(COOKIE_PATH) // propsProvider.getCookiePath() 등으로 변경 가능
                    .httpOnly(HTTP_ONLY)
                    .secure(propsProvider.isCookieSecure())
                    .sameSite(SAME_SITE)
                    .maxAge((int) propsProvider.getRefreshTokenValidity() / 1000)
                    .build();
            cookiesToSet.add(refreshCookie);
            body.put("refreshExpiresIn", propsProvider.getRefreshTokenValidity());
        }

        return TokenTransportResult.builder()
                .body(body)
                .cookiesToSet(cookiesToSet)
                .build();
    }

    @Override
    public TokenTransportResult prepareTokensForClear(TokenService.TokenServicePropertiesProvider propsProvider) {
        List<ResponseCookie> cookiesToRemove = new ArrayList<>();
        ResponseCookie expiredRefreshCookie = ResponseCookie.from(propsProvider.getRefreshTokenCookieName(), "")
                .path(COOKIE_PATH)
                .httpOnly(HTTP_ONLY)
                .secure(propsProvider.isCookieSecure())
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        cookiesToRemove.add(expiredRefreshCookie);

        return TokenTransportResult.builder()
                .cookiesToRemove(cookiesToRemove)
                .body(Map.of("message", "Tokens cleared by server instruction."))
                .build();
    }
}

