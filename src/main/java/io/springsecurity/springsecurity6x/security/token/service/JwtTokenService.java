package io.springsecurity.springsecurity6x.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import io.springsecurity.springsecurity6x.security.enums.TokenType;
import io.springsecurity.springsecurity6x.security.exception.TokenCreationException;
import io.springsecurity.springsecurity6x.security.exception.TokenInvalidException;
import io.springsecurity.springsecurity6x.security.exception.TokenStorageException;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenRequest;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert; // Assert 추가

import java.util.Objects; // Objects 추가
import java.util.stream.Collectors;

@Slf4j
public class JwtTokenService implements TokenService {

    private final TokenCreator tokenCreator;
    private final TokenValidator tokenValidator;
    private final RefreshTokenStore tokenStore;
    private final TokenTransportStrategy transport;
    private final AuthContextProperties props;
    private final ObjectMapper objectMapper;

    public JwtTokenService(TokenValidator tokenValidator, TokenCreator tokenCreator, RefreshTokenStore tokenStore,
                           TokenTransportStrategy transport, AuthContextProperties props, ObjectMapper objectMapper) {
        Assert.notNull(tokenValidator, "tokenValidator cannot be null");
        Assert.notNull(tokenCreator, "tokenCreator cannot be null");
        Assert.notNull(tokenStore, "tokenStore cannot be null");
        Assert.notNull(transport, "transport cannot be null");
        Assert.notNull(props, "props cannot be null");
        Assert.notNull(objectMapper, "objectMapper cannot be null");

        this.tokenCreator = tokenCreator;
        this.tokenValidator = tokenValidator;
        this.tokenStore = tokenStore;
        this.transport = transport;
        this.props = props;
        this.objectMapper = objectMapper;
    }

    @Override
    public String createAccessToken(Authentication authentication, String deviceId) {
        Objects.requireNonNull(authentication, "authentication cannot be null");
        // deviceId가 필수라면 Null 체크 추가
        // Objects.requireNonNull(deviceId, "deviceId cannot be null for access token creation");
        return getToken(authentication, TokenType.ACCESS.name().toLowerCase(), props.getAccessTokenValidity(), deviceId);
    }

    @Override
    public String createRefreshToken(Authentication authentication, String deviceId) {
        Objects.requireNonNull(authentication, "authentication cannot be null");
        // deviceId가 필수라면 Null 체크 추가
        // Objects.requireNonNull(deviceId, "deviceId cannot be null for refresh token creation");
        String token = getToken(authentication, TokenType.REFRESH.name().toLowerCase(), props.getRefreshTokenValidity(), deviceId);
        try {
            tokenStore.save(token, authentication.getName());
        } catch (Exception e) {
            log.error("Failed to save RefreshToken for user: {}, token: {}", authentication.getName(), token, e);
            throw new TokenInvalidException("Failed to save refresh token", e);
        }
        return token;
    }

    private String getToken(Authentication authentication, String tokenType, long validity, String deviceId) {
        TokenRequest.TokenRequestBuilder tokenRequestBuilder = TokenRequest.builder()
                .tokenType(tokenType)
                .username(authentication.getName())
                .roles(authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .validity(validity);

        if (deviceId != null) { // deviceId가 null이 아닐 경우에만 설정
            tokenRequestBuilder.deviceId(deviceId);
        }

        try {
            return tokenCreator.createToken(tokenRequestBuilder.build());
        } catch (Exception e) {
            log.error("Failed to create token: type={}, user={}, deviceId={}", tokenType, authentication.getName(), deviceId, e);
            throw new TokenCreationException("Token creation failed for type " + tokenType, e);
        }
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");

        try {
            if (tokenStore.isBlacklisted(refreshToken)) {
                log.warn("Attempted to refresh a blacklisted refresh token: {}", refreshToken);
                throw new TokenInvalidException("Blacklisted refresh token");
            }

            if (!validateRefreshToken(refreshToken)) {
                log.warn("Invalid refresh token provided for refresh: {}", refreshToken);
                throw new TokenInvalidException("Invalid refresh token");
            }

            Authentication auth = getAuthentication(refreshToken);
            TokenParser parser = tokenValidator.tokenParser();
            if (parser == null) {
                log.error("TokenParser is null, cannot proceed with refresh for token: {}", refreshToken);
                throw new AuthenticationServiceException("Token parser not available for refresh operation");
            }
            ParsedJwt parsedRefreshToken = parser.parse(refreshToken);
            String deviceId = parsedRefreshToken.deviceId();

            String newAccessToken = createAccessToken(auth, deviceId);
            String newRefreshToken = refreshToken;

            boolean rotateEnabled = props.isEnableRefreshToken();
            if (rotateEnabled && tokenValidator.shouldRotateRefreshToken(refreshToken)) {
                tokenStore.remove(refreshToken); // 이전 리프레시 토큰 삭제
                newRefreshToken = createRefreshToken(auth, deviceId); // 새 리프레시 토큰 생성 및 저장 (내부에서 save 호출)
                log.info("Refresh token rotated for user: {}", auth.getName());
            }
            return new RefreshResult(newAccessToken, newRefreshToken);
        } catch (JwtException e) {
            log.warn("JWT processing error during token refresh: {}", e.getMessage());
            throw new TokenInvalidException("Refresh token processing error: " + e.getMessage(), e);

        } catch (TokenStorageException e) {
            log.error("Token storage error during refresh for token: {}", refreshToken, e);
            throw e; // 이미 구체적인 예외이므로 그대로 전파

        } catch (Exception e) { // 기타 예외 처리
            log.error("Unexpected error during token refresh for token: {}", refreshToken, e);
            throw new AuthenticationServiceException("Unexpected error during token refresh", e);
        }
    }

    @Override
    public void blacklistRefreshToken(String refreshToken, String username, String reason) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");
        Objects.requireNonNull(username, "username cannot be null");
        try {
            tokenStore.blacklist(refreshToken, username, reason);
        } catch (Exception e) {
            log.error("Failed to blacklist refresh token for user: {}, token: {}, reason: {}", username, refreshToken, reason, e);
            // 필요시 TokenStorageException 등 구체적인 예외로 변환하여 throw
        }
    }

    // TokenValidator, TokenTransportStrategy 인터페이스 메소드 구현은 기존과 유사하게 유지
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
        try {
            tokenStore.remove(refreshToken);
        } catch (Exception e) {
            log.error("Failed to invalidate/remove refresh token: {}", refreshToken, e);
            // 필요시 TokenStorageException 등 구체적인 예외로 변환하여 throw
        }
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

    @Override
    public ObjectMapper getObjectMapper() {
        return this.objectMapper;
    }
}


