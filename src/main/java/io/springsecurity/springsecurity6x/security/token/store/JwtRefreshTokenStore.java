package io.springsecurity.springsecurity6x.security.token.store;

import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JwtRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final Map<String, TokenInfo> blacklist = new ConcurrentHashMap<>();
    private final TokenParser tokenParser;

    public JwtRefreshTokenStore(TokenParser tokenParser) {
        this.tokenParser = tokenParser;
    }

    private String key(String username, String deviceId) {
        return username + ":" + deviceId;
    }

    @Override
    public void save(String refreshToken, String username) {
        ParsedJwt parsedJwt = tokenParser.parse(refreshToken);
        Instant expiry = parsedJwt.expiration();
        String deviceId = parsedJwt.deviceId();

        // 기존 토큰 블랙리스트 처리
        TokenInfo old = store.get(key(username, deviceId));
        if (old != null) {
            blacklist.put(key(username, deviceId), new TokenInfo(username, Instant.now(), "Duplicate login"));
        }

        store.put(key(username, deviceId), new TokenInfo(username, expiry));
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
        ParsedJwt parsedJwt = tokenParser.parse(token);
        String deviceId = parsedJwt.deviceId();
        blacklist.put(key(username, deviceId), new TokenInfo(username, Instant.now(), reason));
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
