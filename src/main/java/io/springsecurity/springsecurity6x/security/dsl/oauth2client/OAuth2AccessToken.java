package io.springsecurity.springsecurity6x.security.dsl.oauth2client;

import java.time.Instant;

public class OAuth2AccessToken {

    private final String tokenValue;
    private final Instant expiresAt;

    public OAuth2AccessToken(String tokenValue, Instant expiresAt) {
        this.tokenValue = tokenValue;
        this.expiresAt = expiresAt;
    }

    public String tokenValue() {
        return tokenValue;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
