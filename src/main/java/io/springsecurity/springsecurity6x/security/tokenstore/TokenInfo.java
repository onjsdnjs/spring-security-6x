package io.springsecurity.springsecurity6x.security.tokenstore;

import java.time.Instant;

/**
 * 저장소에 보관할 리프레시 토큰 메타정보
 */
public class TokenInfo {
    private final String username;
    private final String salt;
    private final String tokenHash;
    private final Instant expiry;

    public TokenInfo(String username, String salt, String tokenHash, Instant expiry) {
        this.username   = username;
        this.salt       = salt;
        this.tokenHash  = tokenHash;
        this.expiry     = expiry;
    }

    public String getUsername()  { return username; }
    public String getSalt()      { return salt; }
    public String getTokenHash() { return tokenHash; }
    public Instant getExpiry()   { return expiry; }
}
