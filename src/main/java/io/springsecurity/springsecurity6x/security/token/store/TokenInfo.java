package io.springsecurity.springsecurity6x.security.token.store;

import java.time.Instant;

/**
 * 저장소에 보관할 리프레시 토큰 메타정보
 */
public class TokenInfo {
    private final String   username;
    private final Instant  expiry;

    public TokenInfo(String username, Instant expiry) {
        this.username = username;
        this.expiry   = expiry;
    }
    public String getUsername() { return username; }
    public Instant getExpiry()  { return expiry; }
}
