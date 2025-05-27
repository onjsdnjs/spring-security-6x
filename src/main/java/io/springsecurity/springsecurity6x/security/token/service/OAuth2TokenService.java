package io.springsecurity.springsecurity6x.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportResult;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

/**
 * OAuth2 기반 토큰 서비스
 *
 * 현재는 Client Credentials Flow만 지원하며, refresh token을 사용하지 않습니다.
 * 향후 Authorization Code Flow 등을 지원할 경우를 대비한 확장 구조를 포함합니다.
 *
 * @since 2024.12 - 확장 구조 추가
 */
@Slf4j
public class OAuth2TokenService implements TokenService {

    private final TokenCreator tokenCreator;
    private final TokenValidator tokenValidator;
    private final TokenTransportStrategy transport;
    private final AuthContextProperties props;
    private final ObjectMapper objectMapper; // 2024.12 추가

    /**
     * 기존 생성자 (하위 호환성 유지)
     * @deprecated Use constructor with ObjectMapper parameter
     */
    @Deprecated
    public OAuth2TokenService(TokenCreator tokenCreator, TokenValidator tokenValidator,
                              TokenTransportStrategy transport, AuthContextProperties props) {
        this(tokenCreator, tokenValidator, transport, props, new ObjectMapper());
    }

    /**
     * 새로운 생성자 (ObjectMapper 포함)
     * @since 2024.12
     */
    public OAuth2TokenService(TokenCreator tokenCreator, TokenValidator tokenValidator,
                              TokenTransportStrategy transport, AuthContextProperties props,
                              ObjectMapper objectMapper) {
        this.tokenCreator = tokenCreator;
        this.tokenValidator = tokenValidator;
        this.transport = transport;
        this.props = props;
        this.objectMapper = objectMapper;

        log.info("OAuth2TokenService initialized with token store type: {}",
                props.getTokenStoreType());
    }

    @Override
    public String createAccessToken(Authentication authentication, String deviceId) {
        // OAuth2 Client Credentials Flow에서는 deviceId를 사용하지 않음
        return tokenCreator.createToken(null);
    }

    @Override
    public String createRefreshToken(Authentication authentication, String deviceId) {
        /**
         * 향후 Authorization Code Flow 지원 시:
         * 1. OAuth2 인증 서버에서 발급받은 refresh_token을 저장
         * 2. TokenStoreType에 따라 메모리 또는 Redis에 저장
         * 3. 현재는 Client Credentials Flow만 지원하므로 예외 발생
         */
        throw new UnsupportedOperationException(
                "OAuth2 Client Credentials Flow에서는 refresh token을 발급하지 않습니다. " +
                        "Authorization Code Flow를 사용하려면 OAuth2 설정을 변경하세요.");
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        /**
         * 향후 Authorization Code Flow 지원 시:
         * 1. 저장된 refresh_token으로 OAuth2 인증 서버에 토큰 갱신 요청
         * 2. 새로운 access_token과 refresh_token 받기
         * 3. TokenStoreType에 따라 새 refresh_token 저장
         */
        throw new UnsupportedOperationException(
                "OAuth2 Client Credentials Flow에서는 refresh token 갱신을 지원하지 않습니다.");
    }

    @Override
    public boolean validateAccessToken(String token) {
        return tokenValidator.validateAccessToken(token);
    }

    @Override
    public boolean validateRefreshToken(String token) {
        // Client Credentials Flow에서는 refresh_token 사용 안함
        return false;
    }

    @Override
    public void invalidateRefreshToken(String refreshToken) {
        /**
         * 향후 Authorization Code Flow 지원 시:
         * 1. OAuth2 인증 서버에 토큰 취소 요청 (RFC 7009)
         * 2. 로컬 저장소에서도 제거
         */
        log.debug("OAuth2 Client Credentials flow does not support refresh token invalidation");
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
    public String resolveRefreshToken(HttpServletRequest request) {
        return transport.resolveRefreshToken(request);
    }

    @Override
    public TokenTransportStrategy getUnderlyingTokenTransportStrategy() {
        return transport;
    }

    @Override
    public AuthContextProperties properties() {
        return props;
    }

    @Override
    public void blacklistRefreshToken(String refreshToken, String username, String reason) {
        /**
         * 향후 Authorization Code Flow 지원 시:
         * 1. OAuth2 인증 서버가 토큰 취소를 지원하는 경우 API 호출
         * 2. 로컬 블랙리스트에도 추가
         */
        log.debug("OAuth2 token blacklisting is handled by the authorization server");
    }

    @Override
    public ObjectMapper getObjectMapper() {
        return this.objectMapper;
    }

    @Override
    public TokenTransportResult prepareTokensForTransport(String accessToken, String refreshToken) {
        // OAuth2는 주로 헤더 방식 사용
        TokenServicePropertiesProvider propsProvider = createPropertiesProvider();
        return transport.prepareTokensForWrite(accessToken, refreshToken, propsProvider);
    }

    @Override
    public TokenTransportResult prepareClearTokens() {
        TokenServicePropertiesProvider propsProvider = createPropertiesProvider();
        return transport.prepareTokensForClear(propsProvider);
    }

    /**
     * TokenServicePropertiesProvider 생성 헬퍼 메서드
     * @since 2024.12
     */
    private TokenServicePropertiesProvider createPropertiesProvider() {
        return new TokenServicePropertiesProvider() {
            @Override public long getAccessTokenValidity() { return props.getAccessTokenValidity(); }
            @Override public long getRefreshTokenValidity() { return props.getRefreshTokenValidity(); }
            @Override public String getCookiePath() { return "/"; }
            @Override public boolean isCookieSecure() { return props.isCookieSecure(); }
            @Override public String getRefreshTokenCookieName() { return REFRESH_TOKEN; }
            @Override public String getAccessTokenCookieName() { return ACCESS_TOKEN; }
        };
    }
}