package io.springsecurity.springsecurity6x.security.token.store;

import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final JwtParser jwtParser;

    public InMemoryRefreshTokenStore(JwtParser jwtParser) {
        this.jwtParser = jwtParser;
    }

    @Override
    public void store(String refreshToken, String username) {
        ParsedJwt parsedJwt = jwtParser.parse(refreshToken);
        String jti = parsedJwt.id();
        Instant expiry = parsedJwt.expiration();

        store.put(jti, new TokenInfo(username, expiry));
    }

    @Override
    public String getUsername(String refreshToken) {
        try {
            ParsedJwt parsedJwt = jwtParser.parse(refreshToken);
            String jti = parsedJwt.id();

            TokenInfo info = store.get(jti);
            if (info == null) {
                return null;
            }

            // 만료 체크 후 삭제
            if (Instant.now().isAfter(info.expiry())) {
                store.remove(jti);
                return null;
            }

            return info.username();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void remove(String refreshToken) {
        try {
            ParsedJwt parsedJwt = jwtParser.parse(refreshToken);
            String jti = parsedJwt.id();
            store.remove(jti);
        } catch (Exception ignored) {
        }
    }

    @Override
    public JwtParser parser() {
        return jwtParser;
    }
}
