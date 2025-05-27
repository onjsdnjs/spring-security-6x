package io.springsecurity.springsecurity6x.security.token.store;

import io.jsonwebtoken.JwtException;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Objects;

/**
 * RefreshTokenStore의 공통 비즈니스 로직을 담은 추상 클래스
 *
 * JWT 파싱, 검증, 만료 처리 등의 공통 로직을 제공하며,
 * 실제 저장소 작업은 하위 클래스에 위임합니다.
 *
 * @since 2024.12
 */
@Slf4j
@RequiredArgsConstructor
public abstract class AbstractRefreshTokenStore implements RefreshTokenStore {

    protected final TokenParser tokenParser;
    protected final AuthContextProperties props;

    /**
     * 디바이스 키 생성 (username:deviceId)
     */
    protected String deviceKey(String username, String deviceId) {
        Objects.requireNonNull(username, "username cannot be null for deviceKey");
        Objects.requireNonNull(deviceId, "deviceId cannot be null for deviceKey");
        return username + ":" + deviceId;
    }

    @Override
    public void save(String refreshToken, String username) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");
        Objects.requireNonNull(username, "username cannot be null");

        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String deviceId = parsedJwt.deviceId();
            if (deviceId == null) {
                log.warn("deviceId is null in refreshToken, cannot save. User: {}", username);
                return;
            }

            Instant expiry = parsedJwt.expiration();
            if (Instant.now().isAfter(expiry)) {
                log.warn("Token already expired, not saving. User: {}, deviceId: {}", username, deviceId);
                return;
            }

            // 동시 로그인 제한 처리
            handleConcurrentLoginPolicy(username, deviceId);

            // 실제 저장은 구현체에 위임
            doSaveToken(username, deviceId, refreshToken, expiry);

            log.debug("Saved refresh token for user: {}, deviceId: {}", username, deviceId);

        } catch (JwtException e) {
            log.warn("JWT parsing failed - refreshToken save failed. User: {}. Token: {}", username, refreshToken, e);
        } catch (Exception e) {
            log.error("Unexpected error during refreshToken save. User: {}. Token: {}", username, refreshToken, e);
        }
    }

    @Override
    public String getUsername(String refreshToken) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");

        try {
            if (isBlacklisted(refreshToken)) {
                log.warn("Attempt to use blacklisted refresh token (for getUsername): {}", refreshToken);
                return null;
            }

            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            if (deviceId == null) {
                log.warn("deviceId is null in refreshToken, cannot get username. Subject: {}", subject);
                return null;
            }

            TokenInfo tokenInfo = doGetTokenInfo(subject, deviceId);
            if (tokenInfo == null) {
                log.debug("No refresh token found in store for user: {}, deviceId: {}", subject, deviceId);
                return null;
            }

            if (Instant.now().isAfter(tokenInfo.getExpiration())) {
                log.info("Refresh token expired for user: {}, deviceId: {}, removing from store.", subject, deviceId);
                handleExpiredToken(subject, deviceId, refreshToken);
                return null;
            }

            return tokenInfo.getUsername();

        } catch (JwtException e) {
            log.warn("JWT parsing failed - getUsername failed. Token: {}", refreshToken, e);
            return null;
        } catch (Exception e) {
            log.error("Unexpected error during getUsername. Token: {}", refreshToken, e);
            return null;
        }
    }

    @Override
    public void remove(String refreshToken) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");

        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            if (deviceId == null) {
                log.warn("deviceId is null in refreshToken, cannot remove. Subject: {}", subject);
                return;
            }

            doRemoveToken(subject, deviceId);
            log.debug("Removed refresh token from store for user: {}, deviceId: {}", subject, deviceId);

        } catch (JwtException e) {
            log.warn("JWT parsing failed - refreshToken removal failed. Token: {}", refreshToken, e);
        } catch (Exception e) {
            log.error("Unexpected error during refreshToken removal. Token: {}", refreshToken, e);
        }
    }

    @Override
    public void blacklist(String token, String username, String reason) {
        Objects.requireNonNull(token, "token cannot be null");
        Objects.requireNonNull(username, "username cannot be null for blacklist");

        try {
            ParsedJwt parsedJwt = tokenParser.parse(token);
            doBlacklistToken(token, parsedJwt.subject(), parsedJwt.expiration(), reason);
            log.info("Token blacklisted: user={}, reason={}", parsedJwt.subject(), reason);
        } catch (JwtException e) {
            log.warn("JWT parse failed for token blacklist. User: {}. Reason: {}. Using fallback.", username, reason, e);
            // 파싱 실패 시 기본 만료 시간 사용
            Instant fallbackExpiry = Instant.now().plusMillis(props.getRefreshTokenValidity());
            doBlacklistToken(token, username, fallbackExpiry, reason);
        } catch (Exception e) {
            log.error("Unexpected error during token blacklist. Token: {}. User: {}. Reason: {}", token, username, reason, e);
        }
    }

    @Override
    public void blacklistDevice(String username, String deviceId, String reason) {
        Objects.requireNonNull(username, "username cannot be null for device blacklist");
        Objects.requireNonNull(deviceId, "deviceId cannot be null for device blacklist");

        doBlacklistDevice(username, deviceId, reason);
        log.info("Device blacklisted: user={}, deviceId={}, reason={}", username, deviceId, reason);
    }

    /**
     * 동시 로그인 정책 처리
     */
    private void handleConcurrentLoginPolicy(String username, String currentDeviceId) {
        if (!props.isAllowMultipleLogins()) {
            // 단일 로그인 정책: 모든 기존 디바이스 제거
            evictAllUserDevices(username, "Single login enforced");
        } else {
            // 다중 로그인 정책: 최대 동시 로그인 수 제한
            enforceMaxConcurrentLogins(username, currentDeviceId);
        }
    }

    /**
     * 만료된 토큰 처리
     */
    private void handleExpiredToken(String username, String deviceId, String token) {
        doRemoveToken(username, deviceId);
        blacklist(token, username, TokenInfo.REASON_EXPIRED);
    }

    /**
     * 모든 사용자 디바이스 제거
     */
    private void evictAllUserDevices(String username, String reason) {
        for (String deviceId : doGetUserDevices(username)) {
            evictAndBlacklist(username, deviceId, reason);
        }
    }

    /**
     * 최대 동시 로그인 수 제한
     */
    private void enforceMaxConcurrentLogins(String username, String currentDeviceId) {
        int currentCount = doGetUserDeviceCount(username);

        if (currentCount >= props.getMaxConcurrentLogins()) {
            String oldestDeviceId = doGetOldestDevice(username);
            if (oldestDeviceId != null && !oldestDeviceId.equals(currentDeviceId)) {
                evictAndBlacklist(username, oldestDeviceId, "Max concurrent login exceeded");
            }
        }
    }

    /**
     * 디바이스 제거 및 블랙리스트 추가
     */
    private void evictAndBlacklist(String username, String deviceId, String reason) {
        doRemoveToken(username, deviceId);
        blacklistDevice(username, deviceId, reason);
        log.info("Evicted and blacklisted deviceId: {} for user: {} due to: {}", deviceId, username, reason);
    }

    // ========== 추상 메서드 - 하위 클래스에서 구현 ==========

    /**
     * 토큰을 실제로 저장
     */
    protected abstract void doSaveToken(String username, String deviceId, String token, Instant expiration);

    /**
     * 토큰 정보 조회
     */
    protected abstract TokenInfo doGetTokenInfo(String username, String deviceId);

    /**
     * 토큰 제거
     */
    protected abstract void doRemoveToken(String username, String deviceId);

    /**
     * 토큰을 블랙리스트에 추가
     */
    protected abstract void doBlacklistToken(String token, String username, Instant expiration, String reason);

    /**
     * 디바이스를 블랙리스트에 추가
     */
    protected abstract void doBlacklistDevice(String username, String deviceId, String reason);

    /**
     * 사용자의 모든 디바이스 ID 조회
     */
    protected abstract Iterable<String> doGetUserDevices(String username);

    /**
     * 사용자의 디바이스 수 조회
     */
    protected abstract int doGetUserDeviceCount(String username);

    /**
     * 가장 오래된 디바이스 ID 조회
     */
    protected abstract String doGetOldestDevice(String username);
}