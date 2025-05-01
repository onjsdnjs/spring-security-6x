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

        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String deviceId = parsedJwt.deviceId();
            Instant expiry = parsedJwt.expiration();
            String tokenKey = key(username, deviceId);

            if (!props.isAllowMultipleLogins()) {
                store.keySet().stream()
                        .filter(k -> k.startsWith(username + ":"))
                        .forEach(k -> {
                            store.remove(k);
                            blacklist.put(k, new TokenInfo(username, Instant.now(), "Single login enforced"));
                        });
            } else {
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
        } catch (JwtException e) {
            log.warn("JWT 파싱 실패 - 저장 실패. refreshToken: {}", refreshToken, e);
        }
    }

    @Override
    public String getUsername(String refreshToken) {
        try {
            ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
            String subject = parsedJwt.subject();
            String deviceId = parsedJwt.deviceId();
            TokenInfo info = store.get(key(subject, deviceId));
            if (info == null) return null;
            if (Instant.now().isAfter(info.getExpiration())) {
                store.remove(key(subject, deviceId));
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
        } catch (JwtException e) {
            log.warn("JWT 파싱 실패 - 토큰 제거 실패. refreshToken: {}", refreshToken, e);
        }
    }
}
