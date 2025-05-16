package io.springsecurity.springsecurity6x.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult; // 새로운 DTO
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;

public interface TokenService extends TokenProvider, TokenValidator /* TokenTransportStrategy 상속 제거 */ {

    String ACCESS_TOKEN = "accessToken";
    String REFRESH_TOKEN = "refreshToken";
    String ACCESS_TOKEN_HEADER  = "Authorization";
    String REFRESH_TOKEN_HEADER = "X-Refresh-Token";
    String BEARER_PREFIX        = "Bearer ";

    AuthContextProperties properties();
    void blacklistRefreshToken(String refreshToken, String username, String reason);
    record RefreshResult(String accessToken, String refreshToken) {}
    ObjectMapper getObjectMapper(); // 아직 핸들러에서 사용 중이므로 유지

    /**
     * 현재 TokenTransportStrategy에 따라 토큰들을 어떻게 전달할지에 대한 정보를 담은 객체를 반환합니다.
     * 이 객체는 HTTP 응답 헤더/쿠키 설정 정보 및 JSON 본문에 포함될 데이터를 포함할 수 있습니다.
     * 실제 응답 작성은 핸들러가 AuthResponseWriter를 통해 수행합니다.
     */
    TokenTransportResult prepareTokensForTransport(String accessToken, String refreshToken);

    /**
     * 현재 TokenTransportStrategy에 따라 토큰들을 클리어하기 위한 정보를 담은 객체를 반환합니다.
     */
    TokenTransportResult prepareClearTokens();

    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);

    // TokenTransportStrategy를 내부에서만 사용하도록 하고 외부 노출 최소화
    TokenTransportStrategy getUnderlyingTokenTransportStrategy();

    interface TokenServicePropertiesProvider {
        long getAccessTokenValidity();
        long getRefreshTokenValidity();
        String getCookiePath(); // 예시
        boolean isCookieSecure();
        String getRefreshTokenCookieName();
        String getAccessTokenCookieName();
    }
}


