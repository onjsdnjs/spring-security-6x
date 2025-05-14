/*
package io.springsecurity.springsecurity6x.security.token.store;

import io.jsonwebtoken.JwtException;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class JwtRefreshTokenStore2 implements RefreshTokenStore {

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklistByToken = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklistByDevice = new ConcurrentHashMap<>();

    private final Map<String, LinkedHashMap<String, Instant>> userDevices = new ConcurrentHashMap<>();
    private final TokenParser tokenParser;
    private final AuthContextProperties props;

    public JwtRefreshTokenStore2(TokenParser tokenParser, AuthContextProperties props) {
        this.tokenParser = tokenParser;
        this.props = props;
    }

    private String deviceKey(String username, String deviceId) {
        return username + ":" + deviceId;
    }

    @Override
    public void save(String refreshToken, String username) {
        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String deviceId = parsedJwt.deviceId();
            Instant expiry = parsedJwt.expiration();
            String tokenKey = deviceKey(username, deviceId);

            if (!props.isAllowMultipleLogins()) {
                // 모든 사용자 디바이스를 제거 및 블랙리스트
                store.keySet().stream()
                        .filter(k -> k.startsWith(username + ":"))
                        .forEach(k -> evictAndBlacklist(k, username, "Single login enforced"));

            } else {
                // 현재 사용자 디바이스 수 확인
                Map<String, TokenInfo> userDevices = store.entrySet().stream()
                        .filter(e -> e.getKey().startsWith(username + ":"))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

                if (userDevices.size() >= props.getMaxConcurrentLogins()) {
                    String oldestKey = userDevices.entrySet().stream()
                            .min(Comparator.comparing(e -> e.getValue().getExpiration()))
                            .map(Map.Entry::getKey)
                            .orElse(null);

                    if (oldestKey != null) {
                        evictAndBlacklist(oldestKey, username, "Max concurrent login exceeded");
                    }
                }
            }

            store.put(tokenKey, new TokenInfo(username, expiry));

        } catch (JwtException e) {
            log.warn("JWT 파싱 실패 - 저장 실패. refreshToken: {}", refreshToken, e);
        }
    }

    private void evictAndBlacklist(String tokenKey, String username, String reason) {
        store.remove(tokenKey);
        String[] parts = tokenKey.split(":");
        if (parts.length == 2) {
            String deviceId = parts[1];
            blacklistDevice(username, deviceId, reason);
        } else {
            // fallback (예외 처리 등도 가능)
            log.warn("Invalid tokenKey format for eviction: {}", tokenKey);
        }
    }

    @Override
    public String getUsername(String refreshToken) {
        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            TokenInfo info = store.get(deviceKey(subject, deviceId));
            if (info == null) return null;
            if (Instant.now().isAfter(info.getExpiration())) {
                store.remove(deviceKey(subject, deviceId));
                return null;
            }
            return info.getUsername();
        } catch (JwtException e) {
            log.warn("JWT 파싱 실패 - 사용자 조회 실패. refreshToken: {}", refreshToken, e);
            return null;
        }
    }

    @Override
    public void blacklist(String token, String username, String reason) {
        try {
            ParsedJwt parsedJwt = tokenParser.parse(token);
            String subject = parsedJwt.subject();
            Instant expiry = parsedJwt.expiration();
            blacklistByToken.put(token, new TokenInfo(subject, expiry, reason));
        } catch (JwtException e) {
            log.warn("JWT parse failed for token blacklist. Raw token: {}", token, e);
            blacklistByToken.put(token, new TokenInfo(username != null ? username : "ANONYMOUS", Instant.now(), reason));
        }
    }

    public void blacklistDevice(String username, String deviceId, String reason) {
        String key = deviceKey(username, deviceId);
        blacklistByDevice.put(key, new TokenInfo(username, Instant.now(), reason));
    }

    @Override
    public boolean isBlacklisted(String token) {
        if (blacklistByToken.containsKey(token)) {
            return true;
        }
        try {
            ParsedJwt parsedJwt = tokenParser.parse(token);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            return blacklistByDevice.containsKey(deviceKey(subject, deviceId));
        } catch (JwtException e) {
            return false;
        }
    }

    @Override
    public void remove(String refreshToken) {
        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            store.remove(deviceKey(subject, deviceId));
            LinkedHashMap<String, Instant> devices = userDevices.get(subject);
            if (devices != null) {
                devices.remove(deviceId);
            }
        } catch (JwtException e) {
            log.warn("JWT 파싱 실패 - 토큰 제거 실패. refreshToken: {}", refreshToken, e);
        }
    }
}
*/
