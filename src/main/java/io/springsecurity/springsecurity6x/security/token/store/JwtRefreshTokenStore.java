package io.springsecurity.springsecurity6x.security.token.store;

import io.jsonwebtoken.JwtException;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class JwtRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklist = new ConcurrentHashMap<>();
    private final TokenParser tokenParser;
    private final AuthContextProperties props;

    private final Map<String, LinkedHashMap<String, Instant>> userDevices = new ConcurrentHashMap<>();

    public JwtRefreshTokenStore(TokenParser tokenParser, AuthContextProperties props) {
        this.tokenParser = tokenParser;
        this.props = props;
    }

    private String key(String username, String deviceId) {
        return username + ":" + deviceId;
    }

    @Override
    public void save(String refreshToken, String username) {
        ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
        String deviceId = parsedJwt.deviceId();
        Instant expiry = parsedJwt.expiration();

        String tokenKey = key(username, deviceId);

        if (!props.isAllowMultipleLogins()) {
            // 싱글 로그인: 기존 모든 토큰 제거 및 블랙리스트 처리
            store.keySet().stream()
                    .filter(k -> k.startsWith(username + ":"))
                    .forEach(k -> {
                        store.remove(k);
                        blacklist.put(k, new TokenInfo(username, Instant.now(), "Single login enforced"));
                    });
        } else {
            // 멀티 로그인: 허용 개수 초과 시 가장 오래된 토큰 제거
            Map<String, TokenInfo> devices = store.entrySet().stream()
                    .filter(e -> e.getKey().startsWith(username + ":"))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

            if (devices.size() >= props.getMaxConcurrentLogins()) {
                String oldestKey = devices.entrySet().stream()
                        .min(Comparator.comparing(e -> e.getValue().getExpiration()))
                        .map(Map.Entry::getKey)
                        .orElse(null);
                if (oldestKey != null) {
                    store.remove(oldestKey);
                    blacklist.put(oldestKey, new TokenInfo(username, Instant.now(), "Max concurrent login exceeded"));
                }
            }
        }

        store.put(tokenKey, new TokenInfo(username, expiry));
    }

    @Override
    public String getUsername(String refreshToken) {
        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId(); // deviceId 추출 메서드 필요

            TokenInfo info = store.get(key(subject, deviceId));
            if (info == null) return null;
            if (Instant.now().isAfter(info.getExpiration())) {
                store.remove(key(subject, deviceId));
                return null;
            }
            return info.getUsername();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void blacklist(String token, String username, String reason) {
        String deviceId = "UNKNOWN_DEVICE";
        String resolvedUsername = username != null ? username : "ANONYMOUS";

        try {
            ParsedJwt parsedJwt = tokenParser.parse(token);
            deviceId = parsedJwt.deviceId();
            resolvedUsername = parsedJwt.subject(); // 토큰에서 username 추출 (가능한 경우)
        } catch (JwtException e) {
            log.warn("JWT parse failed for blacklist. Still attempting to block. Raw token: {}", token, e);
        }

        // 최종적으로 블랙리스트에 등록
        blacklist.put(key(resolvedUsername, deviceId), new TokenInfo(resolvedUsername, Instant.now(), reason));
    }

    @Override
    public boolean isBlacklisted(String token) {
        try {
            ParsedJwt parsedJwt = tokenParser.parse(token);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            return blacklist.containsKey(key(subject, deviceId));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public void remove(String refreshToken) {
        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            store.remove(key(subject, deviceId));
            LinkedHashMap<String, Instant> devices = userDevices.get(subject);
            if (devices != null) {
                devices.remove(deviceId);
            }
        } catch (Exception e) {
            throw e;
        }
    }
}
