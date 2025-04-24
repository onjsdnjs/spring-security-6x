package io.springsecurity.springsecurity6x.security.token.store;

import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRefreshTokenStore implements RefreshTokenStore{

    private final Map<String, TokenInfo> store = new ConcurrentHashMap<>();
    private final JwtParser parser;

    public InMemoryRefreshTokenStore(JwtParser parser) {
        this.parser = parser;
    }

    @Override
    public void store(String refreshToken, String username) {

        // 1) JWT 서명·만료 검증 및 JTI 추출
        ParsedJwt jwt = parser.parse(refreshToken);
        String   jti = jwt.getId();

        // 2) 슬라이딩 만료: 서버 스토어의 expiry는 항상 now+validity
        Instant expiry = Instant.now()
                .plusMillis(JwtStateStrategy.REFRESH_TOKEN_VALIDITY);

        // 3) JTI → (username, 만료) 매핑
        store.put(jti, new TokenInfo(username, expiry));
    }

    @Override
    public String getUsername(String refreshToken) {
        try {
            ParsedJwt jwt = parser.parse(refreshToken);
            String   jti = jwt.getId();

            TokenInfo info = store.get(jti);
            if (info == null) {
                return null;
            }
            if (Instant.now().isAfter(info.getExpiry())) {
                store.remove(jti);
                return null;
            }
            return info.getUsername();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void remove(String refreshToken) {
        try {
            String jti = parser.parse(refreshToken).getId();
            store.remove(jti);
        } catch (Exception ignored) {}
    }

    @Override
    public JwtParser parser() {
        return parser;
    }
}
