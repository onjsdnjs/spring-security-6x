package io.springsecurity.springsecurity6x.security.token.store;

import io.jsonwebtoken.JwtException;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 메모리 기반 RefreshToken 저장소
 *
 * ConcurrentHashMap을 사용하여 단일 서버 환경에서 토큰을 관리합니다.
 * AbstractRefreshTokenStore를 상속받아 공통 로직은 재사용하고,
 * 메모리 저장소 관련 구현만 제공합니다.
 *
 * @since 2024.12 - AbstractRefreshTokenStore 상속으로 리팩토링
 */
@Slf4j
public class JwtRefreshTokenStore extends AbstractRefreshTokenStore {

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklistByToken = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklistByDevice = new ConcurrentHashMap<>();

    public JwtRefreshTokenStore(TokenParser tokenParser, AuthContextProperties props) {
        super(tokenParser, props);
    }

    @Override
    protected void doSaveToken(String username, String deviceId, String token, Instant expiration) {
        String tokenKey = deviceKey(username, deviceId);
        store.put(tokenKey, new TokenInfo(username, expiration));
    }

    @Override
    protected TokenInfo doGetTokenInfo(String username, String deviceId) {
        String tokenKey = deviceKey(username, deviceId);
        return store.get(tokenKey);
    }

    @Override
    protected void doRemoveToken(String username, String deviceId) {
        String tokenKey = deviceKey(username, deviceId);
        store.remove(tokenKey);
    }

    @Override
    protected void doBlacklistToken(String token, String username, Instant expiration, String reason) {
        blacklistByToken.put(token, new TokenInfo(username, expiration, reason));
    }

    @Override
    protected void doBlacklistDevice(String username, String deviceId, String reason) {
        String key = deviceKey(username, deviceId);
        // 디바이스 블랙리스트는 즉시 적용, 만료 시간은 현재 시간으로 설정
        blacklistByDevice.put(key, new TokenInfo(username, Instant.now(), reason));
    }

    @Override
    protected Iterable<String> doGetUserDevices(String username) {
        return store.keySet().stream()
                .filter(key -> key.startsWith(username + ":"))
                .map(key -> key.substring(username.length() + 1))
                .collect(Collectors.toList());
    }

    @Override
    protected int doGetUserDeviceCount(String username) {
        return (int) store.keySet().stream()
                .filter(key -> key.startsWith(username + ":"))
                .count();
    }

    @Override
    protected String doGetOldestDevice(String username) {
        return store.entrySet().stream()
                .filter(e -> e.getKey().startsWith(username + ":"))
                .min(Comparator.comparing(e -> e.getValue().getExpiration()))
                .map(e -> e.getKey().substring(username.length() + 1))
                .orElse(null);
    }

    @Override
    public boolean isBlacklisted(String token) {
        if (token == null) {
            return false;
        }

        // 토큰 블랙리스트 확인
        if (blacklistByToken.containsKey(token)) {
            return true;
        }

        // 디바이스 블랙리스트 확인
        try {
            ParsedJwt parsedJwt = tokenParser.parse(token);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            if (deviceId == null) {
                return false;
            }

            String deviceKey = deviceKey(subject, deviceId);
            return blacklistByDevice.containsKey(deviceKey);

        } catch (JwtException e) {
            log.trace("JWT parsing failed during isBlacklisted check for token: {}", token, e);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during isBlacklisted check. Token: {}", token, e);
            return false;
        }
    }

    /**
     * 주기적으로 만료된 블랙리스트 항목 정리 (매 시간 실행)
     */
    @Scheduled(fixedRate = 3600000)
    public void cleanupExpiredBlacklistEntries() {
        Instant now = Instant.now();

        // 만료된 토큰 블랙리스트 항목 제거
        blacklistByToken.entrySet().removeIf(entry ->
                entry.getValue().getExpiration() != null && now.isAfter(entry.getValue().getExpiration())
        );

        // 만료된 토큰 저장소 항목 제거
        store.entrySet().removeIf(entry ->
                now.isAfter(entry.getValue().getExpiration())
        );

        log.debug("Cleaned up expired entries from memory store");
    }
}