package io.springsecurity.springsecurity6x.security.token.store;

import io.jsonwebtoken.JwtException;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled; // 스케줄러 사용 시
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class JwtRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklistByToken = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklistByDevice = new ConcurrentHashMap<>(); // (username:deviceId, TokenInfo)

    private final TokenParser tokenParser;
    private final AuthContextProperties props;

    public JwtRefreshTokenStore(TokenParser tokenParser, AuthContextProperties props) {
        Assert.notNull(tokenParser, "tokenParser cannot be null");
        Assert.notNull(props, "props cannot be null");
        this.tokenParser = tokenParser;
        this.props = props;
    }

    private String deviceKey(String username, String deviceId) {
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
                return; // 또는 예외 발생
            }
            Instant expiry = parsedJwt.expiration();
            String currentTokenKey = deviceKey(username, deviceId);

            if (!props.isAllowMultipleLogins()) {
                // 모든 사용자 디바이스를 제거 및 블랙리스트
                store.keySet().stream()
                        .filter(tokenInfo -> tokenInfo.startsWith(username + ":"))
                        .toList() // ConcurrentModificationException 방지를 위해 toList()로 키 수집 후 처리
                        .forEach(keyToEvict -> evictAndBlacklist(keyToEvict, username, "Single login enforced"));
            } else {
                // 현재 사용자 디바이스 수 확인
                Map<String, TokenInfo> currentUserDevices = store.entrySet().stream()
                        .filter(e -> e.getKey().startsWith(username + ":"))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                if (currentUserDevices.size() >= props.getMaxConcurrentLogins()) {
                    currentUserDevices.entrySet().stream()
                            .min(Comparator.comparing(e -> e.getValue().getExpiration()))
                            .map(Map.Entry::getKey)
                            .ifPresent(oldestKey -> evictAndBlacklist(oldestKey, username, "Max concurrent login exceeded"));
                }
            }
            store.put(currentTokenKey, new TokenInfo(username, expiry));
            log.debug("Saved refresh token for user: {}, deviceId: {}", username, deviceId);

        } catch (JwtException e) {
            log.warn("JWT parsing failed - refreshToken save failed. User: {}. Token: {}", username, refreshToken, e);
        } catch (Exception e) {
            log.error("Unexpected error during refreshToken save. User: {}. Token: {}", username, refreshToken, e);
        }
    }

    private void evictAndBlacklist(String tokenKey, String username, String reason) {
        store.remove(tokenKey);
        String[] parts = tokenKey.split(":", 2); // Limit split to 2 parts
        if (parts.length == 2) {
            String deviceId = parts[1];
            blacklistDevice(username, deviceId, reason); // username과 deviceId를 사용
            log.info("Evicted and blacklisted deviceId: {} for user: {} due to: {}", deviceId, username, reason);
        } else {
            log.warn("Invalid tokenKey format for eviction: {}. Cannot blacklist device.", tokenKey);
        }
    }

    @Override
    public String getUsername(String refreshToken) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");
        try {
            if (isBlacklisted(refreshToken)) { // 블랙리스트 먼저 확인
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

            String tokenKey = deviceKey(subject, deviceId);
            TokenInfo info = store.get(tokenKey);

            if (info == null) {
                log.debug("No refresh token found in store for key: {}", tokenKey);
                return null;
            }
            if (Instant.now().isAfter(info.getExpiration())) {
                log.info("Refresh token expired for key: {}, removing from store.", tokenKey);
                store.remove(tokenKey);
                // Optionally, blacklist it as EXPIRED
                blacklist(refreshToken, subject, TokenInfo.REASON_EXPIRED);
                return null;
            }
            return info.getUsername();
        } catch (JwtException e) {
            log.warn("JWT parsing failed - getUsername failed. Token: {}", refreshToken, e);
            return null;
        } catch (Exception e) {
            log.error("Unexpected error during getUsername. Token: {}", refreshToken, e);
            return null;
        }
    }

    @Override
    public void blacklist(String token, String username, String reason) {
        Objects.requireNonNull(token, "token cannot be null");
        Objects.requireNonNull(username, "username cannot be null for blacklist");
        try {
            ParsedJwt parsedJwt = tokenParser.parse(token); // username은 파싱된 subject를 사용하도록 유도
            blacklistByToken.put(token, new TokenInfo(parsedJwt.subject(), parsedJwt.expiration(), reason));
            log.info("Token blacklisted: user={}, reason={}", parsedJwt.subject(), reason);
        } catch (JwtException e) {
            log.warn("JWT parse failed for token blacklist. Raw token: {}. User: {}. Reason: {}. Falling back to provided username.", token, username, reason, e);
            // 파싱 실패 시, 토큰 자체를 키로 사용하고 만료시간은 알 수 없으므로 적절히 설정 (예: 현재 시간 또는 긴 시간)
            blacklistByToken.put(token, new TokenInfo(username, Instant.now().plusSeconds(props.getRefreshTokenValidity()/1000), reason));
        } catch (Exception e) {
            log.error("Unexpected error during token blacklist. Token: {}. User: {}. Reason: {}", token, username, reason, e);
        }
    }

    // username, deviceId를 파라미터로 받도록 수정
    @Override
    public void blacklistDevice(String username, String deviceId, String reason) {
        Objects.requireNonNull(username, "username cannot be null for device blacklist");
        Objects.requireNonNull(deviceId, "deviceId cannot be null for device blacklist");
        String key = deviceKey(username, deviceId);
        // 디바이스 블랙리스트는 즉시 적용, 만료 시간은 현재 시간으로 설정하여 즉시 만료 효과
        blacklistByDevice.put(key, new TokenInfo(username, Instant.now(), reason));
        log.info("Device blacklisted: user={}, deviceId={}, reason={}", username, deviceId, reason);
    }


    @Override
    public boolean isBlacklisted(String token) {
        Objects.requireNonNull(token, "token cannot be null");
        if (blacklistByToken.containsKey(token)) {
            TokenInfo blacklistedTokenInfo = blacklistByToken.get(token);
            // 만약 블랙리스트된 토큰도 만료시간이 있다면 체크 가능
            // if (blacklistedTokenInfo != null && Instant.now().isAfter(blacklistedTokenInfo.getExpiration())) {
            //     blacklistByToken.remove(token); // 만료된 블랙리스트 항목 제거
            //     return false;
            // }
            return true;
        }
        try {
            ParsedJwt parsedJwt = tokenParser.parse(token);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            if (deviceId == null) {
                return false; // deviceId가 없는 토큰은 디바이스 블랙리스트 대상이 아님
            }
            String deviceKey = deviceKey(subject, deviceId);
            TokenInfo blacklistedDeviceInfo = blacklistByDevice.get(deviceKey);
            if (blacklistedDeviceInfo != null) {
                // 디바이스 블랙리스트는 일반적으로 영구적이거나, 관리자에 의해 해제될 때까지 유효
                // 만약 디바이스 블랙리스트에도 만료 개념을 도입한다면 여기서 체크
                return true;
            }
            return false;
        } catch (JwtException e) {
            // 파싱 실패한 토큰은 유효하지 않은 토큰으로 간주, 블랙리스트 여부 확인 불가
            log.trace("JWT parsing failed during isBlacklisted check for token: {}", token, e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during isBlacklisted check. Token: {}", token, e);
            return false; // 예외 발생 시 안전하게 false 반환
        }
    }

    @Override
    public synchronized void remove(String refreshToken) { // synchronized 추가
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");
        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            if (deviceId == null) {
                log.warn("deviceId is null in refreshToken, cannot remove. Subject: {}", subject);
                return;
            }
            String tokenKey = deviceKey(subject, deviceId);
            store.remove(tokenKey);
            log.debug("Removed refresh token from store for key: {}", tokenKey);
        } catch (JwtException e) {
            log.warn("JWT parsing failed - refreshToken removal failed. Token: {}", refreshToken, e);
        } catch (Exception e) {
            log.error("Unexpected error during refreshToken removal. Token: {}", refreshToken, e);
        }
    }

    // 주기적으로 만료된 블랙리스트 항목 정리 (예: 매 시간 실행)
    @Scheduled(fixedRate = 3600000)
    public void cleanupExpiredBlacklistEntries() {
        Instant now = Instant.now();
        blacklistByToken.entrySet().removeIf(entry -> entry.getValue().getExpiration() != null && now.isAfter(entry.getValue().getExpiration()));
        // blacklistByDevice는 보통 만료 개념이 없거나 다른 방식으로 관리되므로 여기서는 제외
        log.info("Cleaned up expired blacklistByToken entries.");
    }
}
